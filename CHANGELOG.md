<!-- markdownlint-disable -->
# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Derive random IV if not given based on key, not in default value to function arguments

## [v1.0.3] - 2024-12-16

### Added
- Added key wrapping/unwrapping via `AES-KW` key support
- Added `generateIV` to generate an appropriate random IV for a given key/algorithm

### Changed
- Minor refactor to reuse encoding/decoding via `_encode()` and `_decode()`

## [v1.0.2] - 2024-12-12

### Added
- Add support for deriving keys from passwords
- Add support for encrypting/decrypting files
- Add new constants for better consistency

## [v1.0.1] - 2024-12-11

### Fixed
- Output correct format and without polyfills

## [v1.0.0] - 2024-12-11

Initial Release
