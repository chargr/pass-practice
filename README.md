# Pass Practice

Use a hardware key everyday? Have a passphrase for emergencies?  Cant rely on a password vault or a securely stored hard copy?

`pass-practice` is a small CLI prompt to help commit passphrases to long term memory by "safely" practicing them without creating unecessary sessions on the services they protect.

Written in go because I wanted to learn go.

## Usage
Add a new password
```
./pass-practice add account1
Password:
Confirm:
```

List passwords
```
./pass-practice list
```

Remove a password from vault
```
./pass-practice del account1
```

Practice a random password from vault
```
./pass-practice
```

Practice a specific password
```
./pass-practice practice account1
```

## Building
Requires `go`
```
make
```

## Password Storage
Passwords are NOT stored and only Argon2 hashes with unique salts are stored in user local data.

`~/.local/share/practice-vault.json` on linux by default.

Still take the necessary precautions to protect your file.

