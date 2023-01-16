webauthn by [Esimios](https://github.com/ESIMIOS)

---  
# Utilitades para el uso de Webauthn (registro, autenticación y firmado con typescript)

Para el uso de esta librería, tomar en cuenta que se utiliza el estándar WebAuthn L1 para un caso de uso en particular:  

* El uso de dispositivos criptográficos autenticadores por hardware portátiles (Llaves FIDO 2 USB, NFC o BLE) que se comunica con el Navegador utilizando el protocolo CTAP (Client to Authenticator Protocol) de FIDO.  

* El valor de authenticatorAttachment se espera como 'cross-platform'

* Los parámetros para la creación de las llaves **pubKeyCredParams** utilizan el algoritmo -7 (COSE), que es ES256 (SHA256withECDSA utilizndo la curva P-256)

* **requireResidentKey** no es requerido (por el momento, pero esto cambiará para permitir llaves residentes e implementar una autenticación passwordless)

* El tipo de **attestation** es 'direct'

* El formato de la respuesta esperada por los autenticadores es 'packed'

* Los transportes esperados para los autenticadores son ["usb", "nfc", "ble"]

* No se utilizan extensiones en los autenticadores















