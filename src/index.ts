/**
 *
 * Desarrollado con ayuda de:
 * https://itnext.io/step-by-step-building-and-publishing-an-npm-typescript-package-44fe7164964c
 * https://www.valentinog.com/blog/jest-coverage/
 */
function isPublicKeyCredentialSupported(): boolean {
  let response = false;
  if (window) {
    if (window.PublicKeyCredential) {
      response = true;
    }
  }
  return response;
}

export { isPublicKeyCredentialSupported };
