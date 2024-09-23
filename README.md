# hashed_password

A rust library to handle password storage.

## Usage

First, create a `HashedPassword`:
```rust
use hashed_password::HashedPassword;

let hashed = HashedPassword::new("MyPlainPassword", b"my-secret");
println!("hashed data: {}", hashed.as_str());
```

Then, validate any plain:
```rust
hashed.validate("MyPlainPassword", b"my-secret"); // true
hashed.validate("MyPlainPassword", b"wrong-secret"); // false
hashed.validate("WrongPlainPassword", b"my-secret"); // false
```
