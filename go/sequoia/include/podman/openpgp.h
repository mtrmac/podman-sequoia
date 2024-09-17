// SPDX-License-Identifier: LGPL-2.0-or-later

#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef enum OpenpgpErrorKind {
  Unknown,
  InvalidArgument,
  IoError,
} OpenpgpErrorKind;

typedef struct OpenpgpImportResult OpenpgpImportResult;

typedef struct OpenpgpMechanism OpenpgpMechanism;

typedef struct OpenpgpSignature OpenpgpSignature;

typedef struct OpenpgpVerificationResult OpenpgpVerificationResult;

typedef struct OpenpgpError {
  enum OpenpgpErrorKind kind;
  const char *message;
} OpenpgpError;

void openpgp_error_free(struct OpenpgpError *err_ptr);

struct OpenpgpMechanism *openpgp_mechanism_new_from_directory(const char *dir_ptr,
                                                              struct OpenpgpError **err_ptr);

struct OpenpgpMechanism *openpgp_mechanism_new_ephemeral(struct OpenpgpError **err_ptr);

void openpgp_mechanism_free(struct OpenpgpMechanism *mechanism_ptr);

void openpgp_signature_free(struct OpenpgpSignature *signature_ptr);

const uint8_t *openpgp_signature_get_data(const struct OpenpgpSignature *signature_ptr,
                                          size_t *data_len);

void openpgp_verification_result_free(struct OpenpgpVerificationResult *result_ptr);

const uint8_t *openpgp_verification_result_get_content(const struct OpenpgpVerificationResult *result_ptr,
                                                       size_t *data_len);

const char *openpgp_verification_result_get_signer(const struct OpenpgpVerificationResult *result_ptr);

struct OpenpgpSignature *openpgp_sign(struct OpenpgpMechanism *mechanism_ptr,
                                      const char *key_handle_ptr,
                                      const char *password_ptr,
                                      const uint8_t *data_ptr,
                                      size_t data_len,
                                      struct OpenpgpError **err_ptr);

struct OpenpgpVerificationResult *openpgp_verify(struct OpenpgpMechanism *mechanism_ptr,
                                                 const uint8_t *signature_ptr,
                                                 size_t signature_len,
                                                 struct OpenpgpError **err_ptr);

void openpgp_import_result_free(struct OpenpgpImportResult *result_ptr);

size_t openpgp_import_result_get_count(const struct OpenpgpImportResult *result_ptr);

const char *openpgp_import_result_get_content(const struct OpenpgpImportResult *result_ptr,
                                              size_t index,
                                              struct OpenpgpError **err_ptr);

struct OpenpgpImportResult *openpgp_import_keys(struct OpenpgpMechanism *mechanism_ptr,
                                                const uint8_t *blob_ptr,
                                                size_t blob_len,
                                                struct OpenpgpError **err_ptr);
