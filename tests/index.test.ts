import { isPublicKeyCredentialSupported } from '../src/index';

test('isPublicKeyCredentialSupported', () => {
  expect(isPublicKeyCredentialSupported()).toBe(false);
});
