# urwarden

A lightweight URL risk scoring CLI tool written in Go.

## Usage

```bash
urwarden <URL>
```

Example:

```bash
urwarden https://bad.example.com/login
```

Output:

```json
{
  "input_url": "https://bad.example.com/login",
  "score": 80,
  "label": "malicious"
}
```
