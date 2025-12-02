# Contributing to blvm-protocol

Thank you for your interest in contributing to blvm-protocol! This document contains **repo-specific guidelines only**. For comprehensive contributing guidelines, see the [BLVM Documentation](https://docs.thebitcoincommons.org/development/contributing.html).

## Quick Links

- **[Complete Contributing Guide](https://docs.thebitcoincommons.org/development/contributing.html)** - Full developer workflow
- **[PR Process](https://docs.thebitcoincommons.org/development/pr-process.html)** - Governance tiers and review process
- **[Testing Infrastructure](https://docs.thebitcoincommons.org/development/testing.html)** - Testing guides

## Code of Conduct

This project follows the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct). By participating, you agree to uphold this code.

## Repository-Specific Guidelines

### Protocol Abstraction

**IMPORTANT:** This code provides protocol abstraction for Bitcoin implementations. Changes must:

1. **Maintain clear separation** between protocol variants
2. **Not break existing protocol implementations**
3. **Handle network parameters correctly**
4. **Preserve protocol evolution capabilities**

### Additional Requirements

- **Protocol Abstraction**: Changes must maintain clean abstraction
- **Variant Support**: Ensure all Bitcoin variants continue to work
- **Backward Compatibility**: Avoid breaking changes to protocol interfaces
- **Test Coverage**: >90% for protocol-critical code

### Development Setup

```bash
git clone https://github.com/BTCDecoded/blvm-protocol.git
cd blvm-protocol
cargo build
cargo test
```

### Running Tests

```bash
# Run all tests
cargo test

# Run with coverage
cargo tarpaulin --out Html

# Run specific test categories
cargo test --test integration_tests
```

### Review Criteria

Reviewers will check:

1. **Correctness** - Does the code work as intended?
2. **Protocol compatibility** - Do all variants continue to work?
3. **Test coverage** - Are all cases covered (>90%)?
4. **Performance** - No regressions?
5. **Documentation** - Is it clear and complete?
6. **Security** - Any potential vulnerabilities?

### Approval Process

- **At least 2 approvals** required for protocol-critical changes
- **Compatibility review** for variant changes
- **Performance review** for protocol selection paths

## Getting Help

- **Documentation**: [docs.thebitcoincommons.org](https://docs.thebitcoincommons.org)
- **Issues**: Use GitHub issues for bugs and feature requests
- **Discussions**: Use GitHub discussions for questions
- **Security**: See [SECURITY.md](SECURITY.md)

Thank you for contributing to blvm-protocol!
