import { isPublicKeyCredentialSupported, createPublicKeyCredential } from '../src/index';

test('isPublicKeyCredentialSupported', () => {
  expect(isPublicKeyCredentialSupported()).toBe(false);
});