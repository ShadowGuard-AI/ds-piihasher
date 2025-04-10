# ds-PIIHasher
A command-line tool that replaces identified Personally Identifiable Information (PII) with consistent, reversible hash values, using libraries like `presidio_analyzer` for PII detection and `bcrypt` for secure hashing. - Focused on Data anonymization and pseudonymization toolkit.  Provides utilities to redact or replace sensitive information within various data formats (CSV, JSON, text files) with realistic, synthetic data. Useful for preparing data for testing or sharing without exposing real user information.

## Install
`git clone https://github.com/ShadowStrikeHQ/ds-piihasher`

## Usage
`./ds-piihasher [params]`

## Parameters
- `--file_type`: No description provided
- `--fields`: No description provided
- `--pii_types`: No description provided
- `--hash`: Enable reversible hashing of PII using bcrypt.
- `--replace`: Enable PII replacement with synthetic data.
- `--seed`: Optional seed for the Faker instance to generate consistent synthetic data across multiple runs.

## License
Copyright (c) ShadowStrikeHQ
