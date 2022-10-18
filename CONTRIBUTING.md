# Contribution

Please read [Auth0's contribution guidelines](https://github.com/auth0/open-source-template/blob/master/GENERAL-CONTRIBUTING.md).

## Environment setup

- Make sure you have node and npm installed
- Run `npm install` to install dependencies
- Follow the local development steps below to get started

## Local development

- `npm install`: install dependencies
- `npm run start:example`: starts development http server at [http://localhost:3000](http://localhost:3000)
- `npm run test`: run unit tests
- `npm run test:end-to-end`: runs integration tests for examples

## Testing

### Adding tests

- Unit tests go inside [test](./test/)
- Integration tests go inside [end-to-end](./end-to-end/)

### Running tests

Run unit and integration tests before opening a PR:

```bash
npm run test
npm run test:end-to-end
```

Also include any information about essential manual tests.