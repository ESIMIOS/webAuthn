//https://www.w3.org/TR/webauthn-1/Overview.html


//https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialRequestOptions
//https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/Attestation_and_Assertion
//https://udn.realityripple.com/docs/Web/API/PublicKeyCredentialCreationOptions/attestation

export const createOptions =  {
    challenge: new Uint8Array([97,98,114,97,99,97,100,97,98,114,97]), //abracadabra
    rp: {
      name: "COFEPRIS TRÁMITES DIGITALES",
      id: "localhost",
    },
    user: {
      id: new Uint8Array([0x55, 0x53, 0x45, 0x52, 0x4e, 0x41, 0x4d, 0x45]),
      name: "USERNAME",
      displayName: "Nombre del Usuario"
    },
    pubKeyCredParams: [{ alg: -7, type: 'public-key' }],
    authenticatorSelection: {
      authenticatorAttachment: 'cross-platform',
      userVerification: 'required',
      requireResidentKey: false
    },
    timeout: 60000,
    attestation: 'direct',
    attestationFormats: ['packed']
  } as PublicKeyCredentialCreationOptions



  //https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential
  //https://udn.realityripple.com/docs/Web/API/PublicKeyCredential
  //https://udn.realityripple.com/docs/Web/API/AuthenticatorResponse
  //https://udn.realityripple.com/docs/Web/API/AuthenticatorAttestationResponse
  export const createdCredential = {
    authenticatorAttachment: "cross-platform",
    id:"4esfJVZKm1laAtIdyCASuMwQ91g9Z_cSyzGQ_A9GnUBU-6OOvwmI1sr6KnIeQD914cn_Np1elnYFhN_7MepnDG001U3btWotPHl7VTgNqLz8wKVdBX-B7oUyAvikFygg",
    rawId: new Uint8Array([225,235,31,37,86,74,155,89,90,2,210,29,200,32,18,184,204,16,247,88,61,103,247,18,203,49,144,252,15,70,157,64,84,251,163,142,191,9,136,214,202,250,42,114,30,64,63,117,225,201,255,54,157,94,150,118,5,132,223,251,49,234,103,12,109,52,213,77,219,181,106,45,60,121,123,85,56,13,168,188,252,192,165,93,5,127,129,238,133,50,2,248,164,23,40,32]).buffer,
    response:{
      attestationObject:new Uint8Array([163,99,102,109,116,102,112,97,99,107,101,100,103,97,116,116,83,116,109,116,163,99,97,108,103,38,99,115,105,103,88,71,48,69,2,32,76,76,209,233,133,201,35,204,182,169,30,28,132,100,95,253,214,217,233,5,157,169,189,125,121,67,91,159,170,166,249,164,2,33,0,226,57,23,152,152,123,141,127,198,245,58,249,165,196,85,93,211,112,243,206,221,166,12,14,244,181,232,134,248,111,78,62,99,120,53,99,130,89,2,63,48,130,2,59,48,130,1,225,160,3,2,1,2,2,16,29,242,181,90,81,220,75,104,133,163,217,158,105,127,237,18,48,10,6,8,42,134,72,206,61,4,3,2,48,73,49,11,48,9,6,3,85,4,6,19,2,85,83,49,29,48,27,6,3,85,4,10,12,20,70,101,105,116,105,97,110,32,84,101,99,104,110,111,108,111,103,105,101,115,49,27,48,25,6,3,85,4,3,12,18,70,101,105,116,105,97,110,32,70,73,68,79,32,67,65,32,48,52,48,32,23,13,49,56,48,53,50,49,48,48,48,48,48,48,90,24,15,50,48,51,51,48,53,50,48,50,51,53,57,53,57,90,48,104,49,11,48,9,6,3,85,4,6,19,2,85,83,49,29,48,27,6,3,85,4,10,12,20,70,101,105,116,105,97,110,32,84,101,99,104,110,111,108,111,103,105,101,115,49,34,48,32,6,3,85,4,11,12,25,65,117,116,104,101,110,116,105,99,97,116,111,114,32,65,116,116,101,115,116,97,116,105,111,110,49,22,48,20,6,3,85,4,3,12,13,70,84,32,70,73,68,79,50,32,48,52,51,48,48,89,48,19,6,7,42,134,72,206,61,2,1,6,8,42,134,72,206,61,3,1,7,3,66,0,4,178,126,14,142,57,0,31,84,236,155,111,79,232,132,25,3,118,69,32,168,118,235,105,141,60,192,13,125,91,77,195,204,217,86,50,163,26,19,172,189,103,243,143,61,98,178,165,160,220,12,165,40,150,64,13,201,173,57,120,139,234,40,128,69,163,129,137,48,129,134,48,29,6,3,85,29,14,4,22,4,20,221,50,68,23,26,103,171,191,82,32,7,115,209,60,207,55,150,174,119,177,48,31,6,3,85,29,35,4,24,48,22,128,20,147,35,112,102,197,29,206,196,171,28,43,173,132,193,243,231,29,206,96,103,48,12,6,3,85,29,19,1,1,255,4,2,48,0,48,19,6,11,43,6,1,4,1,130,229,28,2,1,1,4,4,3,2,4,48,48,33,6,11,43,6,1,4,1,130,229,28,1,1,4,4,18,4,16,238,4,27,206,37,229,76,219,143,134,137,127,214,65,132,100,48,10,6,8,42,134,72,206,61,4,3,2,3,72,0,48,69,2,32,63,22,233,16,178,161,189,127,172,51,212,61,166,129,185,102,56,103,221,111,162,215,203,157,39,71,7,247,252,241,177,177,2,33,0,163,59,184,129,82,57,31,198,82,187,155,125,227,24,50,229,2,107,154,211,227,122,201,79,37,166,244,78,171,243,68,214,89,1,254,48,130,1,250,48,130,1,160,160,3,2,1,2,2,16,24,21,43,65,183,67,174,109,180,21,153,195,177,125,130,9,48,10,6,8,42,134,72,206,61,4,3,2,48,75,49,11,48,9,6,3,85,4,6,19,2,85,83,49,29,48,27,6,3,85,4,10,12,20,70,101,105,116,105,97,110,32,84,101,99,104,110,111,108,111,103,105,101,115,49,29,48,27,6,3,85,4,3,12,20,70,101,105,116,105,97,110,32,70,73,68,79,32,82,111,111,116,32,67,65,48,32,23,13,49,56,48,53,50,48,48,48,48,48,48,48,90,24,15,50,48,51,56,48,53,49,57,50,51,53,57,53,57,90,48,73,49,11,48,9,6,3,85,4,6,19,2,85,83,49,29,48,27,6,3,85,4,10,12,20,70,101,105,116,105,97,110,32,84,101,99,104,110,111,108,111,103,105,101,115,49,27,48,25,6,3,85,4,3,12,18,70,101,105,116,105,97,110,32,70,73,68,79,32,67,65,32,48,52,48,89,48,19,6,7,42,134,72,206,61,2,1,6,8,42,134,72,206,61,3,1,7,3,66,0,4,197,161,22,86,57,138,146,22,252,114,187,40,186,74,105,133,57,191,143,71,43,6,108,200,64,42,157,164,159,208,36,51,235,181,71,103,71,15,93,135,122,156,78,46,155,112,71,210,90,248,91,206,32,61,198,69,81,234,217,219,113,235,184,51,163,102,48,100,48,29,6,3,85,29,14,4,22,4,20,147,35,112,102,197,29,206,196,171,28,43,173,132,193,243,231,29,206,96,103,48,31,6,3,85,29,35,4,24,48,22,128,20,75,189,135,38,17,173,28,137,207,4,88,190,112,210,8,140,107,22,35,183,48,18,6,3,85,29,19,1,1,255,4,8,48,6,1,1,255,2,1,0,48,14,6,3,85,29,15,1,1,255,4,4,3,2,1,6,48,10,6,8,42,134,72,206,61,4,3,2,3,72,0,48,69,2,32,127,181,64,196,63,70,150,22,36,189,19,37,72,180,74,223,4,182,97,113,143,228,44,50,186,95,154,212,12,112,106,181,2,33,0,250,197,166,125,220,213,199,247,145,88,164,25,5,104,153,91,174,199,83,226,122,149,74,78,50,33,247,158,74,96,194,241,104,97,117,116,104,68,97,116,97,88,228,73,150,13,229,136,14,140,104,116,52,23,15,100,118,96,91,143,228,174,185,162,134,50,199,153,92,243,186,131,29,151,99,69,0,0,174,126,238,4,27,206,37,229,76,219,143,134,137,127,214,65,132,100,0,96,225,235,31,37,86,74,155,89,90,2,210,29,200,32,18,184,204,16,247,88,61,103,247,18,203,49,144,252,15,70,157,64,84,251,163,142,191,9,136,214,202,250,42,114,30,64,63,117,225,201,255,54,157,94,150,118,5,132,223,251,49,234,103,12,109,52,213,77,219,181,106,45,60,121,123,85,56,13,168,188,252,192,165,93,5,127,129,238,133,50,2,248,164,23,40,32,165,1,2,3,38,32,1,33,88,32,2,1,144,47,16,24,147,220,231,124,38,238,214,140,205,57,11,51,200,183,6,63,124,229,69,127,177,153,168,107,206,231,34,88,32,83,135,6,163,48,165,242,230,144,180,55,212,47,154,149,54,255,81,249,54,127,199,101,47,94,202,33,253,248,77,205,239]).buffer,
      clientDataJSON:new Uint8Array([123,34,116,121,112,101,34,58,34,119,101,98,97,117,116,104,110,46,99,114,101,97,116,101,34,44,34,99,104,97,108,108,101,110,103,101,34,58,34,89,87,74,121,89,87,78,104,90,71,70,105,99,109,69,34,44,34,111,114,105,103,105,110,34,58,34,104,116,116,112,58,47,47,108,111,99,97,108,104,111,115,116,58,56,48,56,48,34,44,34,99,114,111,115,115,79,114,105,103,105,110,34,58,102,97,108,115,101,125]).buffer
    } as AuthenticatorAttestationResponse, 
    type: "public-key",
    getClientExtensionResults: () => {return {}}
  } as PublicKeyCredential



  //https://udn.realityripple.com/docs/Web/API/PublicKeyCredentialRequestOptions
  export const requestOptions = {
    challenge: new Uint8Array([97,98,114,97,99,97,100,97,98,114,97]), //abracadabra
    allowCredentials: [{
      id: new Uint8Array([225,235,31,37,86,74,155,89,90,2,210,29,200,32,18,184,204,16,247,88,61,103,247,18,203,49,144,252,15,70,157,64,84,251,163,142,191,9,136,214,202,250,42,114,30,64,63,117,225,201,255,54,157,94,150,118,5,132,223,251,49,234,103,12,109,52,213,77,219,181,106,45,60,121,123,85,56,13,168,188,252,192,165,93,5,127,129,238,133,50,2,248,164,23,40,32]),
      type: "public-key",
      transports: ["usb", "nfc", "ble"]
    }],
  } as PublicKeyCredentialRequestOptions


  //https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential
  //https://udn.realityripple.com/docs/Web/API/PublicKeyCredential
  //https://udn.realityripple.com/docs/Web/API/AuthenticatorResponse
  //https://udn.realityripple.com/docs/Web/API/AuthenticatorAssertionResponse
  export const assertion = {
    authenticatorAttachment: "cross-platform",
    id: "4esfJVZKm1laAtIdyCASuMwQ91g9Z_cSyzGQ_A9GnUBU-6OOvwmI1sr6KnIeQD914cn_Np1elnYFhN_7MepnDG001U3btWotPHl7VTgNqLz8wKVdBX-B7oUyAvikFygg",
    rawId: new Uint8Array([225,235,31,37,86,74,155,89,90,2,210,29,200,32,18,184,204,16,247,88,61,103,247,18,203,49,144,252,15,70,157,64,84,251,163,142,191,9,136,214,202,250,42,114,30,64,63,117,225,201,255,54,157,94,150,118,5,132,223,251,49,234,103,12,109,52,213,77,219,181,106,45,60,121,123,85,56,13,168,188,252,192,165,93,5,127,129,238,133,50,2,248,164,23,40,32]).buffer,
    response: {
      authenticatorData: new Uint8Array([73,150,13,229,136,14,140,104,116,52,23,15,100,118,96,91,143,228,174,185,162,134,50,199,153,92,243,186,131,29,151,99,5,0,0,175,76]).buffer,
      clientDataJSON: new Uint8Array([123,34,116,121,112,101,34,58,34,119,101,98,97,117,116,104,110,46,103,101,116,34,44,34,99,104,97,108,108,101,110,103,101,34,58,34,89,87,74,121,89,87,78,104,90,71,70,105,99,109,69,34,44,34,111,114,105,103,105,110,34,58,34,104,116,116,112,58,47,47,108,111,99,97,108,104,111,115,116,58,56,48,56,48,34,44,34,99,114,111,115,115,79,114,105,103,105,110,34,58,102,97,108,115,101,44,34,111,116,104,101,114,95,107,101,121,115,95,99,97,110,95,98,101,95,97,100,100,101,100,95,104,101,114,101,34,58,34,100,111,32,110,111,116,32,99,111,109,112,97,114,101,32,99,108,105,101,110,116,68,97,116,97,74,83,79,78,32,97,103,97,105,110,115,116,32,97,32,116,101,109,112,108,97,116,101,46,32,83,101,101,32,104,116,116,112,115,58,47,47,103,111,111,46,103,108,47,121,97,98,80,101,120,34,125]).buffer,
      signature: new Uint8Array([48,70,2,33,0,186,120,93,193,215,171,158,190,171,116,109,40,0,215,87,219,103,140,244,220,215,112,86,28,132,205,187,229,73,215,204,2,2,33,0,134,119,18,237,127,251,69,51,112,145,0,205,227,53,174,109,212,222,13,235,197,97,16,182,27,200,186,40,238,38,0,122]).buffer,
      userHandle: null
    } as AuthenticatorAssertionResponse,
    type: "public-key",
    getClientExtensionResults: () => {return {}}
  } as PublicKeyCredential