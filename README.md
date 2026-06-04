# ForgeMint

A Simple Forge of KeyStore

## License

See [LICENSE](LICENSE)

## Config

Work dir: `/data/adb/forgemint/`

### target.txt

Each line: package name with mode suffix.

```
<package>!     → generate mode (software key + cert)
<package>?     → patch mode (hardware key + cert replace)
<package>      → auto mode (tee?patch:generate)
```

## Credits

[RaPLT](https://github.com/Dere3046/RaPLT)
