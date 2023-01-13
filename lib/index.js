"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isPublicKeyCredentialSupported = exports.Greeter = void 0;
var Greeter = function (name) { return "Hello ".concat(name); };
exports.Greeter = Greeter;
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