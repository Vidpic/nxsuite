#include "extkeys.h"
#include "nacp.h"
#include "nca.h"
#include "npdm.h"
#include "pfs0.h"
#include "pki.h"
#include "settings.h"
#include "utils.h"
#include "version.h"
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__declspec(dllexport) _Bool
program_nca(const char *exefs, const char *romfs, const char *logo,
            const char *out_dir, const char *sdk_version,
            const char *key_generation, const char *title_id, const char *prodkeys)
{
  hp_settings_t settings;
  memset(&settings, 0, sizeof(settings));

  filepath_init(&settings.out_dir);
  filepath_init(&settings.exefs_dir);
  filepath_init(&settings.romfs_dir);
  filepath_init(&settings.logo_dir);
  filepath_init(&settings.programnca);
  filepath_init(&settings.controlnca);
  filepath_init(&settings.legalnca);
  filepath_init(&settings.htmldocnca);
  filepath_init(&settings.datanca);
  filepath_init(&settings.publicdatanca);
  filepath_init(&settings.metanca);
  filepath_init(&settings.ncadir);
  filepath_init(&settings.cnmt);
  filepath_init(&settings.acid_sig_private_key);
  filepath_init(&settings.nca_sig1_private_key);
  filepath_init(&settings.nca_sig2_private_key);
  filepath_init(&settings.nca_sig2_modulus);

  // Hardcode default temp directory
  filepath_init(&settings.temp_dir);
  filepath_set(&settings.temp_dir, "hacpack_temp");

  // Hardcode default backup directory
  filepath_init(&settings.backup_dir);
  filepath_set(&settings.backup_dir, "hacpack_backup");

  // Keyset
  filepath_t keypath;
  filepath_init(&keypath);
  pki_initialize_keyset(&settings.keyset);

  // Default Settings
  settings.keygeneration = 1;
  settings.sdk_version = 0x000C1100;
  settings.keyareakey = (unsigned char *)calloc(1, 0x10);
  memset(settings.keyareakey, 4, 0x10);

  // General Settings
  settings.file_type = FILE_TYPE_NCA;
  settings.nca_type = NCA_TYPE_PROGRAM;
  settings.nca_disttype = NCA_DISTRIBUTION_DOWNLOAD;

  // Program Directory
  filepath_set(&settings.out_dir, out_dir);

  // ExeFS Directory
  filepath_set(&settings.exefs_dir, exefs);

  // RomFS Directory
  filepath_set(&settings.romfs_dir, romfs);

  // Logo Directory
  filepath_set(&settings.logo_dir, logo);

  // Prodkeys-Setup
  filepath_set(&keypath, prodkeys);
  FILE *keyfile = NULL;
  if (keypath.valid == VALIDITY_VALID)
    keyfile = os_fopen(keypath.os_path, OS_MODE_READ);

  // Try to populate keyfile.
  if (keyfile != NULL)
  {
    printf("Loading '%s' keyset file\n", keypath.char_path);
    extkeys_initialize_keyset(&settings.keyset, keyfile);
    pki_derive_keys(&settings.keyset);
    fclose(keyfile);
  }
  else
  {
    printf("\n");
    fprintf(stderr, "Error: Unable to open keyset file\n");
    return EXIT_FAILURE;
  }

  // SDK Version
  settings.sdk_version = strtoul(sdk_version, NULL, 16);
  // Validating SDK Version
  if (settings.sdk_version < 0x000B0000)
  {
    fprintf(stderr,
            "Error: Invalid SDK version: %08" PRIX32 "\n"
            "SDK version must be equal or greater than: 000B0000\n",
            settings.sdk_version);
    exit(EXIT_FAILURE);
  }

  // Keygeneration
  settings.keygeneration = atoi(key_generation);
  // Validating Keygeneration
  if (settings.keygeneration < 1 || settings.keygeneration > 32)
  {
    fprintf(stderr, "Invalid keygeneration: %i, keygeneration range: 1-32\n",
            settings.keygeneration);
    return EXIT_FAILURE;
  }

  // Title ID
  settings.title_id = strtoull(title_id, NULL, 16);

  // Make sure that header_key exists
  uint8_t has_header_Key = 0;
  for (unsigned int i = 0; i < 0x10; i++)
  {
    if (settings.keyset.header_key[i] != 0)
    {
      has_header_Key = 1;
      break;
    }
  }
  if (has_header_Key == 0)
  {
    fprintf(stderr, "Error: header_key is not present in keyset file\n");
    return EXIT_FAILURE;
  }

  // Make sure that key_area_key_application_keygen exists
  uint8_t has_kek = 0;
  for (unsigned int kekc = 0; kekc < 0x10; kekc++)
  {
    if (settings.keyset.key_area_keys[settings.keygeneration - 1][0][kekc] !=
        0)
    {
      has_kek = 1;
      break;
    }
  }
  if (has_kek == 0)
  {
    fprintf(stderr,
            "Error: key_area_key_application for keygeneration %i is not "
            "present in keyset file\n",
            settings.keygeneration);
    return EXIT_FAILURE;
  }

  // Make sure that titlekek_keygen exists if titlekey is specified
  if (settings.has_title_key == 1)
  {
    uint8_t has_titlekek = 0;
    for (unsigned int tkekc = 0; tkekc < 0x10; tkekc++)
    {
      if (settings.keyset.titlekeks[settings.keygeneration - 1][tkekc] != 0)
      {
        has_titlekek = 1;
        break;
      }
    }
    if (has_titlekek == 0)
    {
      fprintf(stderr,
              "Error: titlekek for keygeneration %i is not present in keyset "
              "file\n",
              settings.keygeneration);
      return EXIT_FAILURE;
    }
  }

  // Make sure that titleid is within valid range
  if (settings.title_id < 0x0100000000000000)
  {
    fprintf(stderr,
            "Error: Bad TitleID: %016" PRIx64 "\n"
            "Valid TitleID range: 0100000000000000 - ffffffffffffffff\n",
            settings.title_id);
  }
  if (settings.title_id > 0x01ffffffffffffff)
    printf("Warning: TitleID %" PRIx64
           " is greater than 01ffffffffffffff and it's not suggested\n",
           settings.title_id);

  // Make sure that outout directory is set
  if (settings.out_dir.valid == VALIDITY_INVALID)
  {
    fprintf(stderr, "Error: Output directory is not specified");
  }

  if (settings.file_type == FILE_TYPE_NCA)
  {
    // Remove existing temp directory and create a new one
    printf("Removing existing temp directory\n");
    filepath_remove_directory(&settings.temp_dir);
    printf("Creating temp directory\n");
    os_makedir(settings.temp_dir.os_path);

    // Create backup directory
    printf("Creating backup directory\n");
    os_makedir(settings.backup_dir.os_path);
    // Add titleid to backup folder path
    filepath_append(&settings.backup_dir, "%016" PRIx64, settings.title_id);
    os_makedir(settings.backup_dir.os_path);
  }

  // Create output directory
  printf("Creating output directory\n");
  os_makedir(settings.out_dir.os_path);

  printf("\n");

  if (settings.exefs_dir.valid == VALIDITY_INVALID)
  {
    fprintf(stderr, "Error: exefs filepath is not set\n");
  }
  else if (((settings.nca_sig2_private_key.valid == VALIDITY_VALID) &&
            (settings.nca_sig2_modulus.valid == VALIDITY_INVALID)) ||
           ((settings.nca_sig2_private_key.valid == VALIDITY_INVALID) &&
            (settings.nca_sig2_modulus.valid == VALIDITY_VALID)))
  {
    fprintf(stderr, "Error: Both nca signature 2 private key and public key "
                    "filepaths must be valid\n");
  }
  printf("----> Processing NPDM\n");
  npdm_process(&settings);
  printf("\n");
  nca_create_program(&settings);

  // Remove temp directory
  if (settings.file_type == FILE_TYPE_NCA)
  {
    printf("\n");
    printf("Removing created temp directory\n");
    filepath_remove_directory(&settings.temp_dir);
  }

  printf("\nDone.\n");

  free(settings.keyareakey);
  return EXIT_SUCCESS;
}

__declspec(dllexport) _Bool
meta_nca(const char *legal_nca, const char *control_nca, const char *htmldoc_nca,
         const char *program_nca, const char *out_dir, const char *sdk_version,
         const char *key_generation, const char *title_id,
         const char *titleversion, const char *prodkeys)
{
  hp_settings_t settings;
  memset(&settings, 0, sizeof(settings));

  filepath_init(&settings.out_dir);
  filepath_init(&settings.exefs_dir);
  filepath_init(&settings.romfs_dir);
  filepath_init(&settings.logo_dir);
  filepath_init(&settings.programnca);
  filepath_init(&settings.controlnca);
  filepath_init(&settings.legalnca);
  filepath_init(&settings.htmldocnca);
  filepath_init(&settings.datanca);
  filepath_init(&settings.publicdatanca);
  filepath_init(&settings.metanca);
  filepath_init(&settings.ncadir);
  filepath_init(&settings.cnmt);
  filepath_init(&settings.acid_sig_private_key);
  filepath_init(&settings.nca_sig1_private_key);
  filepath_init(&settings.nca_sig2_private_key);
  filepath_init(&settings.nca_sig2_modulus);

  // Hardcode default temp directory
  filepath_init(&settings.temp_dir);
  filepath_set(&settings.temp_dir, "hacpack_temp");

  // Hardcode default backup directory
  filepath_init(&settings.backup_dir);
  filepath_set(&settings.backup_dir, "hacpack_backup");

  // Keyset
  filepath_t keypath;
  filepath_init(&keypath);
  pki_initialize_keyset(&settings.keyset);

  // Default Settings
  settings.keygeneration = 1;
  settings.sdk_version = 0x000C1100;
  settings.keyareakey = (unsigned char *)calloc(1, 0x10);
  memset(settings.keyareakey, 4, 0x10);

  // General Settings
  settings.file_type = FILE_TYPE_NCA;
  settings.nca_type = NCA_TYPE_META;
  settings.nca_disttype = NCA_DISTRIBUTION_DOWNLOAD;
  settings.title_type = TITLE_TYPE_APPLICATION;

  // Program Directory
  filepath_set(&settings.out_dir, out_dir);

  // Program NCA
  filepath_set(&settings.programnca, program_nca);

  // Control NCA
  filepath_set(&settings.controlnca, control_nca);

  // Legal NCA
  filepath_set(&settings.legalnca, legal_nca);

  // Html Document NCA
  filepath_set(&settings.htmldocnca, htmldoc_nca);

  // Title Version
  settings.title_version = strtoul(titleversion, NULL, 16);

  // Prodkeys-Setup
  filepath_set(&keypath, prodkeys);
  FILE *keyfile = NULL;
  if (keypath.valid == VALIDITY_VALID)
    keyfile = os_fopen(keypath.os_path, OS_MODE_READ);

  // Try to populate keyfile.
  if (keyfile != NULL)
  {
    printf("Loading '%s' keyset file\n", keypath.char_path);
    extkeys_initialize_keyset(&settings.keyset, keyfile);
    pki_derive_keys(&settings.keyset);
    fclose(keyfile);
  }
  else
  {
    printf("\n");
    fprintf(stderr, "Error: Unable to open keyset file\n");
    return EXIT_FAILURE;
  }

  // SDK Version
  settings.sdk_version = strtoul(sdk_version, NULL, 16);
  // Validating SDK Version
  if (settings.sdk_version < 0x000B0000)
  {
    fprintf(stderr,
            "Error: Invalid SDK version: %08" PRIX32 "\n"
            "SDK version must be equal or greater than: 000B0000\n",
            settings.sdk_version);
    exit(EXIT_FAILURE);
  }

  // Keygeneration
  settings.keygeneration = atoi(key_generation);
  // Validating Keygeneration
  if (settings.keygeneration < 1 || settings.keygeneration > 32)
  {
    fprintf(stderr, "Invalid keygeneration: %i, keygeneration range: 1-32\n",
            settings.keygeneration);
    return EXIT_FAILURE;
  }

  // Title ID
  settings.title_id = strtoull(title_id, NULL, 16);

  // Make sure that header_key exists
  uint8_t has_header_Key = 0;
  for (unsigned int i = 0; i < 0x10; i++)
  {
    if (settings.keyset.header_key[i] != 0)
    {
      has_header_Key = 1;
      break;
    }
  }
  if (has_header_Key == 0)
  {
    fprintf(stderr, "Error: header_key is not present in keyset file\n");
    return EXIT_FAILURE;
  }

  // Make sure that key_area_key_application_keygen exists
  uint8_t has_kek = 0;
  for (unsigned int kekc = 0; kekc < 0x10; kekc++)
  {
    if (settings.keyset.key_area_keys[settings.keygeneration - 1][0][kekc] !=
        0)
    {
      has_kek = 1;
      break;
    }
  }
  if (has_kek == 0)
  {
    fprintf(stderr,
            "Error: key_area_key_application for keygeneration %i is not "
            "present in keyset file\n",
            settings.keygeneration);
    return EXIT_FAILURE;
  }

  // Make sure that titlekek_keygen exists if titlekey is specified
  if (settings.has_title_key == 1)
  {
    uint8_t has_titlekek = 0;
    for (unsigned int tkekc = 0; tkekc < 0x10; tkekc++)
    {
      if (settings.keyset.titlekeks[settings.keygeneration - 1][tkekc] != 0)
      {
        has_titlekek = 1;
        break;
      }
    }
    if (has_titlekek == 0)
    {
      fprintf(stderr,
              "Error: titlekek for keygeneration %i is not present in keyset "
              "file\n",
              settings.keygeneration);
      return EXIT_FAILURE;
    }
  }

  // Make sure that titleid is within valid range
  if (settings.title_id < 0x0100000000000000)
  {
    fprintf(stderr,
            "Error: Bad TitleID: %016" PRIx64 "\n"
            "Valid TitleID range: 0100000000000000 - ffffffffffffffff\n",
            settings.title_id);
  }
  if (settings.title_id > 0x01ffffffffffffff)
    printf("Warning: TitleID %" PRIx64
           " is greater than 01ffffffffffffff and it's not suggested\n",
           settings.title_id);

  // Make sure that outout directory is set
  if (settings.out_dir.valid == VALIDITY_INVALID)
  {
    fprintf(stderr, "Error: Output directory is not specified");
  }

  if (settings.file_type == FILE_TYPE_NCA)
  {
    // Remove existing temp directory and create a new one
    printf("Removing existing temp directory\n");
    filepath_remove_directory(&settings.temp_dir);
    printf("Creating temp directory\n");
    os_makedir(settings.temp_dir.os_path);

    // Create backup directory
    printf("Creating backup directory\n");
    os_makedir(settings.backup_dir.os_path);
    // Add titleid to backup folder path
    filepath_append(&settings.backup_dir, "%016" PRIx64, settings.title_id);
    os_makedir(settings.backup_dir.os_path);
  }

  // Create output directory
  printf("Creating output directory\n");
  os_makedir(settings.out_dir.os_path);

  printf("\n");

  if (settings.cnmt.valid == VALIDITY_VALID)
    nca_create_meta(&settings);
  else if (settings.title_type == 0)
  {
    fprintf(stderr, "Error: invalid titletype\n");
  }
  else if (settings.has_title_key)
  {
    fprintf(stderr, "Error: Titlekey is not supported for metadata nca\n");
  }
  else if ((settings.programnca.valid == VALIDITY_INVALID ||
            settings.controlnca.valid == VALIDITY_INVALID) &&
           settings.title_type == TITLE_TYPE_APPLICATION)
  {
    fprintf(stderr, "Error: --programnca and/or --controlnca is not set\n");
  }
  else if (settings.title_type == TITLE_TYPE_ADDON &&
           settings.publicdatanca.valid == VALIDITY_INVALID)
  {
    fprintf(stderr, "Error: --publicdatanca is not set\n");
  }
  else if (settings.title_type == TITLE_TYPE_SYSTEMPROGRAM &&
           settings.programnca.valid == VALIDITY_INVALID)
  {
    fprintf(stderr, "Error: --programnca is not set\n");
  }
  else if (settings.title_type == TITLE_TYPE_SYSTEMDATA &&
           settings.datanca.valid == VALIDITY_INVALID)
  {
    fprintf(stderr, "Error: --datanca is not set\n");
  }
  else
    nca_create_meta(&settings);

  // Remove temp directory
  if (settings.file_type == FILE_TYPE_NCA)
  {
    printf("\n");
    printf("Removing created temp directory\n");
    filepath_remove_directory(&settings.temp_dir);
  }

  printf("\nDone.\n");

  free(settings.keyareakey);
  return EXIT_SUCCESS;
}

__declspec(dllexport) _Bool nsp(const char *nca_dir, const char *out_dir, const char *title_id, const char *prodkeys)
{
  hp_settings_t settings;
  memset(&settings, 0, sizeof(settings));

  filepath_init(&settings.out_dir);
  filepath_init(&settings.exefs_dir);
  filepath_init(&settings.romfs_dir);
  filepath_init(&settings.logo_dir);
  filepath_init(&settings.programnca);
  filepath_init(&settings.controlnca);
  filepath_init(&settings.legalnca);
  filepath_init(&settings.htmldocnca);
  filepath_init(&settings.datanca);
  filepath_init(&settings.publicdatanca);
  filepath_init(&settings.metanca);
  filepath_init(&settings.ncadir);
  filepath_init(&settings.cnmt);
  filepath_init(&settings.acid_sig_private_key);
  filepath_init(&settings.nca_sig1_private_key);
  filepath_init(&settings.nca_sig2_private_key);
  filepath_init(&settings.nca_sig2_modulus);

  // Hardcode default temp directory
  filepath_init(&settings.temp_dir);
  filepath_set(&settings.temp_dir, "hacpack_temp");

  // Hardcode default backup directory
  filepath_init(&settings.backup_dir);
  filepath_set(&settings.backup_dir, "hacpack_backup");

  // Keyset
  filepath_t keypath;
  filepath_init(&keypath);
  pki_initialize_keyset(&settings.keyset);

  // Default Settings
  settings.keygeneration = 1;
  settings.sdk_version = 0x000C1100;
  settings.keyareakey = (unsigned char *)calloc(1, 0x10);
  memset(settings.keyareakey, 4, 0x10);

  // General Settings
  settings.file_type = FILE_TYPE_NSP;

  // NSP Directory
  filepath_set(&settings.out_dir, out_dir);

  // NCA Directory
  filepath_set(&settings.ncadir, nca_dir);

  // Prodkeys-Setup
  filepath_set(&keypath, prodkeys);
  FILE *keyfile = NULL;
  if (keypath.valid == VALIDITY_VALID)
    keyfile = os_fopen(keypath.os_path, OS_MODE_READ);

  // Try to populate keyfile.
  if (keyfile != NULL)
  {
    printf("Loading '%s' keyset file\n", keypath.char_path);
    extkeys_initialize_keyset(&settings.keyset, keyfile);
    pki_derive_keys(&settings.keyset);
    fclose(keyfile);
  }
  else
  {
    printf("\n");
    fprintf(stderr, "Error: Unable to open keyset file\n");
    return EXIT_FAILURE;
  }

  // Title ID
  settings.title_id = strtoull(title_id, NULL, 16);

  // Make sure that header_key exists
  uint8_t has_header_Key = 0;
  for (unsigned int i = 0; i < 0x10; i++)
  {
    if (settings.keyset.header_key[i] != 0)
    {
      has_header_Key = 1;
      break;
    }
  }
  if (has_header_Key == 0)
  {
    fprintf(stderr, "Error: header_key is not present in keyset file\n");
    return EXIT_FAILURE;
  }

  // Make sure that key_area_key_application_keygen exists
  uint8_t has_kek = 0;
  for (unsigned int kekc = 0; kekc < 0x10; kekc++)
  {
    if (settings.keyset.key_area_keys[settings.keygeneration - 1][0][kekc] !=
        0)
    {
      has_kek = 1;
      break;
    }
  }
  if (has_kek == 0)
  {
    fprintf(stderr,
            "Error: key_area_key_application for keygeneration %i is not "
            "present in keyset file\n",
            settings.keygeneration);
    return EXIT_FAILURE;
  }

  // Make sure that titlekek_keygen exists if titlekey is specified
  if (settings.has_title_key == 1)
  {
    uint8_t has_titlekek = 0;
    for (unsigned int tkekc = 0; tkekc < 0x10; tkekc++)
    {
      if (settings.keyset.titlekeks[settings.keygeneration - 1][tkekc] != 0)
      {
        has_titlekek = 1;
        break;
      }
    }
    if (has_titlekek == 0)
    {
      fprintf(stderr,
              "Error: titlekek for keygeneration %i is not present in keyset "
              "file\n",
              settings.keygeneration);
      return EXIT_FAILURE;
    }
  }

  // Make sure that titleid is within valid range
  if (settings.title_id < 0x0100000000000000)
  {
    fprintf(stderr,
            "Error: Bad TitleID: %016" PRIx64 "\n"
            "Valid TitleID range: 0100000000000000 - ffffffffffffffff\n",
            settings.title_id);
  }
  if (settings.title_id > 0x01ffffffffffffff)
    printf("Warning: TitleID %" PRIx64
           " is greater than 01ffffffffffffff and it's not suggested\n",
           settings.title_id);

  // Make sure that outout directory is set
  if (settings.out_dir.valid == VALIDITY_INVALID)
  {
    fprintf(stderr, "Error: Output directory is not specified");
  }

  // Create output directory
  printf("Creating output directory\n");
  os_makedir(settings.out_dir.os_path);

  printf("\n");

  if (settings.ncadir.valid != VALIDITY_INVALID)
  {
    // Create NSP
    printf("----> Creating NSP:\n");
    filepath_t nsp_file_path;
    filepath_init(&nsp_file_path);
    filepath_copy(&nsp_file_path, &settings.out_dir);
    filepath_append(&nsp_file_path, "%016" PRIx64 ".nsp", settings.title_id);
    uint64_t pfs0_size;
    pfs0_build(&settings.ncadir, &nsp_file_path, &pfs0_size);
    printf("\n----> Created NSP: %s\n", nsp_file_path.char_path);
  }
  else
  {
    fprintf(stderr, "Error: --ncadir is not set\n");
  }

  printf("\nDone.\n");

  free(settings.keyareakey);
  return EXIT_SUCCESS;
}
