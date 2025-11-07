
## Test Guide

### Install dependencies

```bash
pnpm install
```

### Run tests

```bash
npm test
```

### Generate coverage report

```bash
npm run test:coverage
```

Output example:

```
 RUN  v1.6.1 /Users/weaver/Desktop/eliza-dot-aes
      Coverage enabled with v8

 ✓ packages/common/src/index.test.ts (15)
 ✓ packages/sr25519-aes/src/index.test.ts (3)
 ✓ packages/ecdsa-aes/src/index.test.ts (4)
 ✓ packages/ed25519-aes/src/index.test.ts (3)

 Test Files  4 passed (4)
      Tests  25 passed (25)
   Start at  18:02:38
   Duration  475ms (transform 100ms, setup 0ms, collect 373ms, tests 628ms, environment 0ms, prepare 279ms)

 % Coverage report from v8
-----------------|---------|----------|---------|---------|-------------------
File             | % Stmts | % Branch | % Funcs | % Lines | Uncovered Line #s 
-----------------|---------|----------|---------|---------|-------------------
All files        |   99.29 |     87.5 |   95.45 |   99.29 |                   
 common/src      |   99.04 |    83.87 |    92.3 |   99.04 |                   
  index.ts       |   98.75 |    82.75 |   91.66 |   98.75 | 76,86-87          
  interfaces.ts  |     100 |      100 |     100 |     100 |                   
  utils.ts       |     100 |      100 |     100 |     100 |                   
 ecdsa-aes/src   |     100 |      100 |     100 |     100 |                   
  index.ts       |     100 |      100 |     100 |     100 |                   
 ed25519-aes/src |     100 |      100 |     100 |     100 |                   
  index.ts       |     100 |      100 |     100 |     100 |                   
 sr25519-aes/src |     100 |      100 |     100 |     100 |                   
  index.ts       |     100 |      100 |     100 |     100 |                   
-----------------|---------|----------|---------|---------|-------------------
➜  eliza-dot-aes git:(main) 
```