/*
 * This file was automatically generated from openpgp.h,
 * which is covered by the following license:
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
VOID_FUNC(void, openpgp_error_free, (struct OpenpgpError *err_ptr), (err_ptr))
FUNC(struct OpenpgpMechanism *, openpgp_mechanism_new_from_directory, (const char *dir_ptr, struct OpenpgpError **err_ptr), (dir_ptr, err_ptr))
FUNC(struct OpenpgpMechanism *, openpgp_mechanism_new_ephemeral, (const uint8_t *keyring_ptr, size_t keyring_len, struct OpenpgpError **err_ptr), (keyring_ptr, keyring_len, err_ptr))
VOID_FUNC(void, openpgp_mechanism_free, (struct OpenpgpMechanism *mechanism_ptr), (mechanism_ptr))
VOID_FUNC(void, openpgp_signature_free, (struct OpenpgpSignature *signature_ptr), (signature_ptr))
FUNC(const uint8_t *, openpgp_signature_get_data, (const struct OpenpgpSignature *signature_ptr, size_t *data_len), (signature_ptr, data_len))
VOID_FUNC(void, openpgp_verification_result_free, (struct OpenpgpVerificationResult *result_ptr), (result_ptr))
FUNC(const uint8_t *, openpgp_verification_result_get_content, (const struct OpenpgpVerificationResult *result_ptr, size_t *data_len), (result_ptr, data_len))
FUNC(const char *, openpgp_verification_result_get_signer, (const struct OpenpgpVerificationResult *result_ptr), (result_ptr))
FUNC(struct OpenpgpSignature *, openpgp_sign, (struct OpenpgpMechanism *mechanism_ptr, const char *key_handle_ptr, const char *password_ptr, const uint8_t *data_ptr, size_t data_len, struct OpenpgpError **err_ptr), (mechanism_ptr, key_handle_ptr, password_ptr, data_ptr, data_len, err_ptr))
FUNC(struct OpenpgpVerificationResult *, openpgp_verify, (struct OpenpgpMechanism *mechanism_ptr, const uint8_t *signature_ptr, size_t signature_len, struct OpenpgpError **err_ptr), (mechanism_ptr, signature_ptr, signature_len, err_ptr))
