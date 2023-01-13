"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isPublicKeyCredentialSupported = void 0;
function isPublicKeyCredentialSupported() {
    var response = false;
    if (window) {
        if (window.PublicKeyCredential) {
            response = true;
        }
    }
    return response;
}
exports.isPublicKeyCredentialSupported = isPublicKeyCredentialSupported;
//# sourceMappingURL=index.js.map