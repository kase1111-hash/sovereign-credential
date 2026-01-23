# Contributing to Sovereign Credential

Thank you for your interest in contributing to Sovereign Credential! This document provides guidelines and instructions for contributing.

## Getting Started

### Prerequisites

- Node.js 18.0.0 or higher
- npm or pnpm
- Git

### Setting Up the Development Environment

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/sovereign-credential.git
   cd sovereign-credential
   ```
3. Install dependencies:
   ```bash
   npm install
   ```
4. Copy the environment template:
   ```bash
   cp .env.example .env
   ```
5. Compile the contracts:
   ```bash
   npm run compile
   ```
6. Run the tests to ensure everything is working:
   ```bash
   npm test
   ```

## Development Workflow

### Branching Strategy

- `main` - Stable release branch
- `develop` - Development branch for integration
- Feature branches should be created from `develop` with descriptive names:
  - `feature/add-credential-expiration`
  - `fix/issuer-registry-validation`
  - `docs/update-api-reference`

### Making Changes

1. Create a new branch for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes following the coding standards below

3. Write or update tests as needed

4. Run the full test suite:
   ```bash
   npm test
   ```

5. Run linting and formatting:
   ```bash
   npm run lint
   npm run format
   ```

6. Commit your changes with a clear message:
   ```bash
   git commit -m "Add feature: description of your changes"
   ```

7. Push to your fork and submit a pull request

## Coding Standards

### Solidity

- Follow the [Solidity Style Guide](https://docs.soliditylang.org/en/latest/style-guide.html)
- Use Solidity 0.8.28 or compatible version
- All public/external functions must have NatSpec documentation
- Use custom errors instead of require strings for gas efficiency
- Keep functions focused and modular

### TypeScript

- Use TypeScript strict mode
- Follow ESLint configuration in `.eslintrc.js`
- Use meaningful variable and function names
- Add JSDoc comments for public APIs

### Testing

- Write tests for all new functionality
- Maintain test coverage above 80%
- Use descriptive test names that explain what is being tested
- Include both positive and negative test cases

### Commit Messages

Use clear, descriptive commit messages:

- `feat:` - New features
- `fix:` - Bug fixes
- `docs:` - Documentation changes
- `test:` - Test additions or modifications
- `refactor:` - Code refactoring
- `chore:` - Maintenance tasks

Example: `feat: add credential renewal functionality`

## Pull Request Process

1. Ensure all tests pass and there are no linting errors
2. Update documentation if you're changing public APIs
3. Add a clear description of your changes in the PR
4. Link any related issues
5. Request review from maintainers
6. Address any feedback from code review

### PR Requirements

- All CI checks must pass
- At least one maintainer approval required
- No merge conflicts with the target branch

## Testing

### Running Tests

```bash
# Run all tests
npm test

# Run tests with coverage
npm run test:coverage

# Run tests with gas reporting
npm run test:gas

# Run circuit tests
npm run circuits:test
```

### Writing Tests

- Place unit tests in `test/` directory
- Place integration tests in `test/integration/`
- Use fixtures in `test/fixtures/` for test data
- Follow existing test patterns and naming conventions

## Zero-Knowledge Circuits

If contributing to ZK circuits:

1. Place circuit files in `circuits/` directory
2. Update compilation scripts as needed
3. Add circuit tests in `circuits/test/`
4. Document any new circuit parameters

### Circuit Development

```bash
# Compile circuits
npm run circuits:compile

# Run trusted setup (development only)
npm run circuits:setup

# Run circuit tests
npm run circuits:test
```

## Documentation

- Update relevant documentation when making changes
- API changes require updates to `docs/API.md`
- New features should be documented in appropriate guides
- Keep the README.md up to date

## Security

If you discover a security vulnerability:

1. **Do NOT open a public issue**
2. Review our [Security Policy](docs/SECURITY.md)
3. Report vulnerabilities responsibly through the appropriate channels

## Questions and Support

- Open an issue for bugs or feature requests
- Check existing issues before creating new ones
- Provide clear reproduction steps for bugs

## License

By contributing to Sovereign Credential, you agree that your contributions will be licensed under the CC0 1.0 Universal license.
