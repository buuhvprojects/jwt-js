# `@buuhv/jwt-js`

JWT is a service class to your manage the sessions of your application


## Getting started

`npm install @buuhv/jwt-js --save`

## Usage

```javascript
import JWT from '@buuhv/jwt-js';

const jwtService = new JWT('SECRET_KEY', 'ISS');

//expires is optional and you can use any value inside object
const newToken = jwtService.register({
    expires: new Date().getTime() 'optional'
    'OBJECT DATA'
});

const isValid = jwtService.checkJWT('OBJECT WITH HEADERS OF REQUEST');
if (isValid.status === false) console.log(isValid.message);

const jwtData = jwtService.data('OBJECT WITH HEADERS OF REQUEST');
if (jwtData.status === true) console.log(jwtData.data);
if (jwtData.status === false) console.log(jwtData.message);

```
---

## Request Object with Headers Example

```
req: {
    headers: {
        Authorization|authorization: 'Bearer ....'
    };
}
```

---

## Contributors

This module was extracted from `Crypto-Js` core. Please reffer to https://github.com/geeknection/jwt-js/contributors for the complete list of contributors.

## License
The library is released under the MIT licence. For more information see `LICENSE`.