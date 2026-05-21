# GraphQL-Sicherheit — Tiefenanalyse

**Wird geladen, wenn** GraphQL-Server erkannt wird (Apollo, GraphQL Yoga, Hot Chocolate, graphql-java, gqlgen, Strawberry, Graphene, Lighthouse, Mercurius, Hasura, PostGraphile, GraphQL.NET, Juniper, async-graphql).

GraphQL hat eigene Klassen von Schwachstellen, die OWASP API Top 10 nur teilweise abdeckt. Dieses Modul behandelt GraphQL-spezifische Angriffsvektoren in der Tiefe.

## 1. Introspection in Production

**CWE-200 / CWE-538** — Information Disclosure. Standard-aktiviert, oft vergessen in Production.

**Detection:**
```bash
rg -n "introspection.*true|IntrospectionQuery|GraphiQL|playground.*true" --type=ts --type=js --type=py
rg -n "ApolloServer|GraphQLYoga|StrawberryConfig|GraphQL\\.Server" -A 5
```

**Unsafe (Apollo Server 4):**
```typescript
const server = new ApolloServer({
  typeDefs, resolvers,
  // introspection defaults to NODE_ENV !== 'production', aber häufig falsch gesetzt
  introspection: true,
});
```

**Safe:**
```typescript
const server = new ApolloServer({
  typeDefs, resolvers,
  introspection: process.env.NODE_ENV !== 'production',
  plugins: process.env.NODE_ENV === 'production'
    ? [ApolloServerPluginLandingPageDisabled()]
    : [ApolloServerPluginLandingPageLocalDefault()],
});
```

**Bypass-Awareness:** Selbst bei deaktivierter Introspection helfen Field-Suggestions bei der Schema-Rekonstruktion (siehe Punkt 7).

## 2. Query Complexity / Depth Limit Missing

**CWE-770 / CWE-400** — Resource Exhaustion. Ein einziger Request kann den Server umlegen.

**Angriffs-Pattern — Nested Recursion:**
```graphql
query Doom {
  user(id: "1") {
    posts { author { posts { author { posts { author { ... } } } } } }
  }
}
```

**Detection:**
```bash
rg -n "depthLimit|costAnalysis|complexity|maxDepth|validationRules" --type=ts --type=js --type=py
# Negative match — Modul fehlt
rg -n "ApolloServer|new GraphQL" -B 2 -A 30 | rg -v "depthLimit|complexity"
```

**Safe (graphql-depth-limit + graphql-query-complexity):**
```typescript
import depthLimit from 'graphql-depth-limit';
import { createComplexityLimitRule } from 'graphql-validation-complexity';

const server = new ApolloServer({
  typeDefs, resolvers,
  validationRules: [
    depthLimit(7),                          // max 7 nested levels
    createComplexityLimitRule(1000, {        // max 1000 cost
      onCost: (cost) => logger.info({cost}),
    }),
  ],
});
```

**Python (Strawberry):**
```python
from strawberry.extensions import QueryDepthLimiter, ValidationCache

schema = strawberry.Schema(query=Query, extensions=[
    QueryDepthLimiter(max_depth=7),
    ValidationCache(maxsize=100),
])
```

## 3. Batching Attacks

**CWE-770** — Mehrere Operationen pro HTTP-Request umgehen Rate-Limits.

**Angriff:**
```json
[
  {"query": "mutation { login(user:\"admin\", pass:\"a\") { token } }"},
  {"query": "mutation { login(user:\"admin\", pass:\"b\") { token } }"},
  {"query": "mutation { login(user:\"admin\", pass:\"c\") { token } }"}
  // ... 10000 weitere
]
```

**Detection:**
```bash
rg -n "batch.*true|allowBatchedHttpRequests" --type=ts --type=js
rg -n "executeBatch|batchScheduleFn" --type=ts
```

**Safe — Batch-Größe begrenzen oder Batching deaktivieren:**
```typescript
const server = new ApolloServer({
  allowBatchedHttpRequests: false,  // wenn nicht zwingend nötig
});

// Wenn doch nötig: Größe limitieren + jede Operation rate-limiten
app.use('/graphql', (req, res, next) => {
  if (Array.isArray(req.body) && req.body.length > 5) {
    return res.status(400).json({error: 'Max 5 operations per batch'});
  }
  next();
});
```

## 4. Alias Overloading — Rate Limit Bypass

**CWE-770** — Aliase erlauben mehrfache Aufrufe derselben Operation im selben Request.

**Angriff:**
```graphql
mutation BruteForce {
  a1: login(user: "admin", pass: "p1") { token }
  a2: login(user: "admin", pass: "p2") { token }
  a3: login(user: "admin", pass: "p3") { token }
  # ... 1000 weitere Aliase
}
```

**Detection-Pattern:** Server lässt Aliase auf rate-limited mutations zu.

**Safe — Alias-Anzahl validieren oder pro Field rate-limiten:**
```typescript
import { createRateLimitDirective } from 'graphql-rate-limit-directive';

const rateLimitDirective = createRateLimitDirective({
  identifyContext: (ctx) => ctx.user?.id ?? ctx.ip,
});

const typeDefs = gql`
  directive @rateLimit(max: Int!, window: String!) on FIELD_DEFINITION
  type Mutation {
    login(user: String!, pass: String!): AuthPayload
      @rateLimit(max: 5, window: "1m")
  }
`;
```

**Zusätzlich — Alias-Limit auf Query-Ebene:**
```typescript
import { createMaxAliasesRule } from '@escape.tech/graphql-armor-max-aliases';
const server = new ApolloServer({
  validationRules: [createMaxAliasesRule({ n: 5 })],
});
```

## 5. Field Duplication & Directive Overloading

**CWE-770** — Gleiches Feld 1000x in einer Query → kostspielige Resolver-Calls.

**Angriff:**
```graphql
query { user(id:"1") { name name name name name name ... } }
```

**Safe — graphql-armor max-directives + max-tokens:**
```typescript
import { ApolloArmor } from '@escape.tech/graphql-armor';

const armor = new ApolloArmor({
  maxDepth:     { n: 7 },
  maxAliases:   { n: 5 },
  maxDirectives:{ n: 5 },
  maxTokens:    { n: 1000 },
  costLimit:    { maxCost: 5000 },
});

const server = new ApolloServer({ ...armor.protect() });
```

## 6. Broken Object Level Authorization (BOLA) in Resolvers

**CWE-639 / OWASP API1:2023** — Resolver akzeptiert ID ohne Tenant-Check.

**Unsafe:**
```typescript
const resolvers = {
  Query: {
    document: async (_, { id }, { user }) => {
      return await db.document.findUnique({ where: { id } });
      // ⚠️ Keine Prüfung ob user.tenantId === document.tenantId
    },
  },
};
```

**Safe:**
```typescript
const resolvers = {
  Query: {
    document: async (_, { id }, { user }) => {
      const doc = await db.document.findUnique({ where: { id } });
      if (!doc) return null;
      if (doc.tenantId !== user.tenantId) {
        throw new GraphQLError('Not authorized', {
          extensions: { code: 'FORBIDDEN' },
        });
      }
      return doc;
    },
  },
};
```

**Verallgemeinert — AuthZ-Layer pro Resolver via Shield/Permissions:**
```typescript
import { shield, rule } from 'graphql-shield';

const ownsDocument = rule()(async (_, { id }, { user }) => {
  const doc = await db.document.findUnique({ where: { id }});
  return doc?.tenantId === user.tenantId || new Error('Forbidden');
});

const permissions = shield({
  Query: { document: ownsDocument },
}, { fallbackRule: deny });
```

## 7. Field Suggestions Leaking Schema

**CWE-200** — Auch ohne Introspection: `did you mean ...?` Fehler verraten Felder.

**Detection:**
```bash
rg -n "DidYouMean|suggestField|fieldSuggestions" --type=ts --type=js
```

**Safe — Suggestions in Production deaktivieren:**
```typescript
import { NoSchemaIntrospectionCustomRule } from 'graphql';
import { createBlockFieldSuggestionsRule } from '@escape.tech/graphql-armor-block-field-suggestions';

const server = new ApolloServer({
  validationRules: [
    NoSchemaIntrospectionCustomRule,
    createBlockFieldSuggestionsRule(),
  ],
});
```

## 8. CSRF via GET / SimpleRequest Bypass

**CWE-352** — GraphQL über GET oder als application/x-www-form-urlencoded → SimpleRequest, CSRF.

**Detection:**
```bash
rg -n "csrfPrevention|csrf:.*false|allowGet" --type=ts --type=js
```

**Safe — Apollo Server 4:**
```typescript
const server = new ApolloServer({
  csrfPrevention: true,  // erzwingt Preflight (x-apollo-operation-name oder content-type: application/json)
});
```

**Manuell:**
```typescript
app.use('/graphql', (req, res, next) => {
  if (req.method === 'POST' && req.headers['content-type'] !== 'application/json') {
    return res.status(400).json({error: 'Must be application/json'});
  }
  next();
});
```

## 9. Mutation via GET (Cache Poisoning, Logs, Referer Leak)

**CWE-598** — Mutations sollten NIE über GET erreichbar sein.

**Safe:**
```typescript
// Apollo: ab v4 default deaktiviert für mutations, aber prüfen:
const server = new ApolloServer({
  allowMutationViaGet: false,  // explizit
});
```

## 10. SSRF via Resolver (URL-Parameter)

**CWE-918** — Resolver fetched URL aus User-Input.

**Unsafe:**
```typescript
const resolvers = {
  Query: {
    fetchUrl: async (_, { url }) => {
      const res = await fetch(url);  // ⚠️ SSRF
      return res.text();
    },
  },
};
```

**Safe — Allowlist + IP-Resolution + DNS-Pinning:**
```typescript
import { LookupAddress } from 'dns';
import ipaddr from 'ipaddr.js';

async function safeFetch(url: string) {
  const u = new URL(url);
  if (!['https:'].includes(u.protocol)) throw new Error('Invalid protocol');
  if (!ALLOWED_HOSTS.includes(u.hostname)) throw new Error('Host not allowed');

  const addresses = await dns.promises.resolve4(u.hostname);
  for (const addr of addresses) {
    const ip = ipaddr.parse(addr);
    if (ip.range() !== 'unicast') throw new Error('IP in restricted range');
  }
  return fetch(url);
}
```

## 11. Mass Assignment via Mutation Inputs

**CWE-915 / OWASP API6:2023**

**Unsafe:**
```typescript
const resolvers = {
  Mutation: {
    updateUser: async (_, { input }, { user }) => {
      return await db.user.update({ where: { id: user.id }, data: input });
      // ⚠️ input könnte { isAdmin: true } enthalten
    },
  },
};
```

**Safe — Schema-getriebene Whitelist:**
```graphql
input UpdateUserInput {
  name: String
  email: String
  # bewusst KEIN isAdmin, KEIN role, KEIN tenantId
}
```
GraphQL erzwingt Schema-Validation — aber der TypeScript-Typ in `data` muss auch eng gefasst sein.

## 12. N+1 → DoS via Nested Lists

**CWE-770** — Nested Lists ohne DataLoader = N×M DB-Queries.

**Detection:**
```bash
rg -n "type.*\[.*\]" graphql/ schemas/
rg -n "DataLoader|dataloader" --type=ts --type=js --type=py
```

**Safe — DataLoader:**
```typescript
import DataLoader from 'dataloader';

const userLoader = new DataLoader<string, User>(async (ids) => {
  const users = await db.user.findMany({ where: { id: { in: [...ids] }}});
  return ids.map(id => users.find(u => u.id === id));
});

const resolvers = {
  Post: {
    author: (post) => userLoader.load(post.authorId),  // batched + cached pro request
  },
};
```

## 13. Persisted Queries / APQ Misuse

**CWE-770 / CWE-444** — Wenn APQ (Automatic Persisted Queries) aktiviert ohne Allowlist:
- Cache-Pollution (unsigned APQ + GET → CDN-Cache-Vergiftung)
- DoS via Hash-Collision

**Safe:**
```typescript
const server = new ApolloServer({
  persistedQueries: {
    cache: redisCache,
    ttl: 900,
  },
  // Für maximale Sicherheit: nur Persisted Queries erlauben
});

// In Production: nur vorab signierte Queries erlauben
import { useAPQ } from '@graphql-yoga/plugin-apq';
```

## 14. Subscriptions Auth-Bypass

**CWE-287** — WebSocket-Subscription wird oft nicht authentifiziert.

**Unsafe:**
```typescript
const wsServer = new WebSocketServer({ server, path: '/graphql' });
useServer({ schema }, wsServer);
// ⚠️ Keine Auth im Connection-Init
```

**Safe:**
```typescript
useServer({
  schema,
  onConnect: async (ctx) => {
    const token = ctx.connectionParams?.authorization;
    const user = await verifyToken(token);
    if (!user) return false;  // schließt Connection
    (ctx.extra as any).user = user;
  },
  context: (ctx) => ({ user: (ctx.extra as any).user }),
}, wsServer);
```

## 15. Error Verbosity → Information Disclosure

**CWE-209** — Stacktraces, DB-Fehler, interne Pfade.

**Safe:**
```typescript
const server = new ApolloServer({
  formatError: (formattedError, error) => {
    logger.error({ error });
    if (process.env.NODE_ENV === 'production') {
      return { message: 'Internal server error', extensions: { code: formattedError.extensions?.code } };
    }
    return formattedError;
  },
});
```

## 16. Federation / Apollo Gateway Trust-Issues

**CWE-345** — Subgraph-Trust ohne mTLS, `@inaccessible`-Fehler.

**Detection:**
```bash
rg -n "@inaccessible|@key|@external|@requires|@provides" --type=graphql
rg -n "IntrospectAndCompose|RemoteGraphQLDataSource"
```

**Risiken:**
- Subgraph erreichbar ohne mTLS → Bypass Gateway-Auth
- `@inaccessible` falsch gesetzt → interne Fields exposed
- Header-Forwarding ohne Filter → Sensible Header an Subgraphs

## 17. Schema-Direktive `@requiresScopes` korrekt setzen

**CWE-862** — Defense-in-Depth durch Schema-Direktiven:

```graphql
directive @requiresScopes(scopes: [[String!]!]!) on FIELD_DEFINITION

type Mutation {
  deleteUser(id: ID!): Boolean @requiresScopes(scopes: [["admin:write"]])
  updateBilling(id: ID!): Bill   @requiresScopes(scopes: [["billing:write", "tenant:owner"]])
}
```

## Tooling-Empfehlungen

- **graphql-armor** (multi-Server-Support): Aliases, Depth, Tokens, Cost, Block-Suggestions
- **graphql-shield**: deklarative Permissions
- **graphql-rate-limit-directive**: feldbasiertes Rate-Limiting
- **graphql-query-complexity**: Cost-Analysis
- **DataLoader**: N+1
- **InQL / Clairvoyance / GraphCrawler**: für Pentest-Validierung (nur in Test-Umgebung!)

## Severity-Heuristik

| Befund | Default-Severity | Bedingungen für Eskalation |
|--------|------------------|-----------------------------|
| Introspection in Prod | Medium | + sensitive Schemas → High |
| Depth/Complexity fehlt | High | öffentlich erreichbar → Critical |
| BOLA in Resolver | High | Multi-Tenant SaaS → Critical |
| Subscription ohne Auth | High | sensible Daten → Critical |
| Field Suggestions an | Low | + komplexes Schema → Medium |
| Batching ohne Limit | Medium | + login-Mutation → High |
| Alias-Overloading möglich | Medium | + auth/payment → High |
| CSRF Prevention aus | Medium | Cookie-Auth → High |
| Mass Assignment | High | Admin-Felder im Input → Critical |
| N+1 ohne DataLoader | Low | + tief verschachtelt → Medium |
| Error verbose in Prod | Low | + DB-Errors → Medium |
| APQ ohne Allowlist | Medium |
| Federation ohne mTLS | High |

## Referenzen

- OWASP API Security Top 10 (2023)
- OWASP GraphQL Cheat Sheet
- "GraphQL Vulnerabilities" — Escape Technology
- "GraphQL Security: 13 Vulnerabilities" — Inigo
- CWE-770, CWE-639, CWE-200, CWE-918, CWE-352, CWE-915
