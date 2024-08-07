#include "extkeys.h"
#include "nax0.h"
#include "nca.h"
#include "nso.h"
#include "packages.h"
#include "pki.h"
#include "save.h"
#include "settings.h"
#include "types.h"
#include "utils.h"
#include "xci.h"
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

typedef struct
{
  _Bool status;
  uint64_t content_size;
  uint64_t title_id;
  char sdk_version[20];
  const char *distrubution_type;
  const char *content_type;
  char master_key_rev[20];
} NCAInfo;

__declspec(dllexport) _Bool nsp(const char *nsp, const char *out_dir, const char *prodkeys)
{
  hactool_ctx_t tool_ctx;
  nca_ctx_t nca_ctx;
  filepath_t keypath;

  nca_init(&nca_ctx);
  memset(&tool_ctx, 0, sizeof(tool_ctx));
  filepath_init(&keypath);
  nca_ctx.tool_ctx = &tool_ctx;
  nca_ctx.is_cli_target = true;

  // General-Setup
  nca_ctx.tool_ctx->file_type = FILETYPE_PFS0;
  nca_ctx.tool_ctx->action |= ACTION_EXTRACT;
  nca_ctx.tool_ctx->settings.skip_key_warnings = 1;

  // Outdir-Setup
  tool_ctx.settings.out_dir_path.enabled = 1;
  filepath_set(&tool_ctx.settings.out_dir_path.path, out_dir);

  // Prodkeys-Setup
  pki_initialize_keyset(&tool_ctx.settings.keyset, KEYSET_RETAIL);
  filepath_set(&keypath, prodkeys);

  FILE *keyfile = NULL;
  if (keypath.valid == VALIDITY_VALID)
  {
    keyfile = os_fopen(keypath.os_path, OS_MODE_READ);
  }
  if (keyfile != NULL)
  {
    extkeys_initialize_settings(&tool_ctx.settings, keyfile);
    if (tool_ctx.settings.has_sdseed)
    {
      for (unsigned int key = 0; key < 2; key++)
      {
        for (unsigned int i = 0; i < 0x20; i++)
        {
          tool_ctx.settings.keyset.sd_card_key_sources[key][i] ^=
              tool_ctx.settings.sdseed[i & 0xF];
        }
      }
    }
    pki_derive_keys(&tool_ctx.settings.keyset);
    fclose(keyfile);
  }

  // Open NSP-File
  if ((tool_ctx.file = fopen(nsp, "rb")) == NULL &&
      tool_ctx.file_type != FILETYPE_BOOT0)
  {
    fprintf(stderr, "unable to open %s: %s\n", nsp, strerror(errno));
    return EXIT_FAILURE;
  }

  // Process NSP-File
  switch (tool_ctx.file_type)
  {
  case FILETYPE_PFS0:
  {
    pfs0_ctx_t pfs0_ctx;
    memset(&pfs0_ctx, 0, sizeof(pfs0_ctx));
    pfs0_ctx.file = tool_ctx.file;
    pfs0_ctx.tool_ctx = &tool_ctx;
    pfs0_process(&pfs0_ctx);
    if (pfs0_ctx.header)
    {
      free(pfs0_ctx.header);
    }
    if (pfs0_ctx.npdm)
    {
      free(pfs0_ctx.npdm);
    }
    break;
  }
  default:
  {
    fprintf(stderr, "Unknown File Type!\n\n");
  }
  }

  if (tool_ctx.settings.known_titlekeys.titlekeys != NULL)
  {
    free(tool_ctx.settings.known_titlekeys.titlekeys);
  }

  if (tool_ctx.file != NULL)
  {
    fclose(tool_ctx.file);
  }
  printf("Done!\n");
  return EXIT_SUCCESS;
}

__declspec(dllexport) _Bool
decrypt_nca(const char *nca, const char *out_dir, const char *titlekey, const char *prodkeys)
{
  hactool_ctx_t tool_ctx;
  hactool_ctx_t base_ctx;
  nca_ctx_t nca_ctx;
  filepath_t keypath;

  nca_init(&nca_ctx);
  memset(&tool_ctx, 0, sizeof(tool_ctx));
  memset(&base_ctx, 0, sizeof(base_ctx));
  filepath_init(&keypath);
  nca_ctx.tool_ctx = &tool_ctx;
  nca_ctx.is_cli_target = true;

  // General-Setup
  nca_ctx.tool_ctx->file_type = FILETYPE_NCA;
  base_ctx.file_type = FILETYPE_NCA;
  nca_ctx.tool_ctx->action = ACTION_EXTRACT;
  nca_ctx.tool_ctx->settings.skip_key_warnings = 1;

  // Outdir-Setup for plaintext
  filepath_set(&nca_ctx.tool_ctx->settings.plaintext_path, out_dir);

  // Prodkeys-Setup
  pki_initialize_keyset(&tool_ctx.settings.keyset, KEYSET_RETAIL);
  filepath_set(&keypath, prodkeys);

  FILE *keyfile = NULL;
  if (keypath.valid == VALIDITY_VALID)
  {
    keyfile = os_fopen(keypath.os_path, OS_MODE_READ);
  }
  if (keyfile != NULL)
  {
    extkeys_initialize_settings(&tool_ctx.settings, keyfile);
    if (tool_ctx.settings.has_sdseed)
    {
      for (unsigned int key = 0; key < 2; key++)
      {
        for (unsigned int i = 0; i < 0x20; i++)
        {
          tool_ctx.settings.keyset.sd_card_key_sources[key][i] ^=
              tool_ctx.settings.sdseed[i & 0xF];
        }
      }
    }
    pki_derive_keys(&tool_ctx.settings.keyset);
    fclose(keyfile);
  }

  // Titlekey-Setup
  parse_hex_key(nca_ctx.tool_ctx->settings.cli_titlekey, titlekey, 16);
  nca_ctx.tool_ctx->settings.has_cli_titlekey = 1;

  // Open NSP-File
  if ((tool_ctx.file = fopen(nca, "rb")) == NULL &&
      tool_ctx.file_type != FILETYPE_BOOT0)
  {
    fprintf(stderr, "unable to open %s: %s\n", nca, strerror(errno));
    return EXIT_FAILURE;
  }

  // Process NCA-File
  switch (tool_ctx.file_type)
  {
  case FILETYPE_NCA:
  {
    if (nca_ctx.tool_ctx->base_nca_ctx != NULL)
    {
      memcpy(&base_ctx.settings.keyset, &tool_ctx.settings.keyset, sizeof(nca_keyset_t));
      base_ctx.settings.known_titlekeys = tool_ctx.settings.known_titlekeys;
      nca_ctx.tool_ctx->base_nca_ctx->tool_ctx = &base_ctx;
      nca_process(nca_ctx.tool_ctx->base_nca_ctx);
      int found_romfs = 0;
      for (unsigned int i = 0; i < 4; i++)
      {
        if (nca_ctx.tool_ctx->base_nca_ctx->section_contexts[i].is_present && nca_ctx.tool_ctx->base_nca_ctx->section_contexts[i].type == ROMFS)
        {
          found_romfs = 1;
          break;
        }
      }
      if (found_romfs == 0)
      {
        fprintf(stderr, "Unable to locate RomFS in base NCA!\n");
        return EXIT_FAILURE;
      }
    }

    nca_ctx.file = tool_ctx.file;
    nca_process(&nca_ctx);
    nca_free_section_contexts(&nca_ctx);

    if (nca_ctx.tool_ctx->base_file_type == BASEFILE_FAKE)
    {
      nca_ctx.tool_ctx->base_file = NULL;
    }

    if (nca_ctx.tool_ctx->base_file != NULL)
    {
      fclose(nca_ctx.tool_ctx->base_file);
      if (nca_ctx.tool_ctx->base_file_type == BASEFILE_NCA)
      {
        nca_free_section_contexts(nca_ctx.tool_ctx->base_nca_ctx);
        free(nca_ctx.tool_ctx->base_nca_ctx);
      }
    }
    break;
  }
  default:
  {
    fprintf(stderr, "Unknown File Type!\n\n");
  }
  }

  if (tool_ctx.settings.known_titlekeys.titlekeys != NULL)
  {
    free(tool_ctx.settings.known_titlekeys.titlekeys);
  }

  if (tool_ctx.file != NULL)
  {
    fclose(tool_ctx.file);
  }
  printf("Done!\n");
  return EXIT_SUCCESS;
}

__declspec(dllexport) _Bool extract_romfs(const char *base_nca, const char *update_nca, const char *out_dir, const char *titlekey, const char *prodkeys)
{
  hactool_ctx_t tool_ctx;
  hactool_ctx_t base_ctx;
  nca_ctx_t nca_ctx;
  filepath_t keypath;

  nca_init(&nca_ctx);
  memset(&tool_ctx, 0, sizeof(tool_ctx));
  memset(&base_ctx, 0, sizeof(base_ctx));
  filepath_init(&keypath);
  nca_ctx.tool_ctx = &tool_ctx;
  nca_ctx.is_cli_target = true;

  // General-Setup
  nca_ctx.tool_ctx->file_type = FILETYPE_NCA;
  base_ctx.file_type = FILETYPE_NCA;
  nca_ctx.tool_ctx->action = ACTION_EXTRACT;
  nca_ctx.tool_ctx->settings.skip_key_warnings = 1;

  // RomFS-DIR-Setup
  nca_ctx.tool_ctx->settings.romfs_dir_path.enabled = 1;
  filepath_set(&nca_ctx.tool_ctx->settings.romfs_dir_path.path, out_dir);

  // Prodkeys-Setup
  pki_initialize_keyset(&tool_ctx.settings.keyset, KEYSET_RETAIL);
  filepath_set(&keypath, prodkeys);

  FILE *keyfile = NULL;
  if (keypath.valid == VALIDITY_VALID)
  {
    keyfile = os_fopen(keypath.os_path, OS_MODE_READ);
  }

  if (keyfile != NULL)
  {
    extkeys_initialize_settings(&tool_ctx.settings, keyfile);
    if (tool_ctx.settings.has_sdseed)
    {
      for (unsigned int key = 0; key < 2; key++)
      {
        for (unsigned int i = 0; i < 0x20; i++)
        {
          tool_ctx.settings.keyset.sd_card_key_sources[key][i] ^=
              tool_ctx.settings.sdseed[i & 0xF];
        }
      }
    }
    pki_derive_keys(&tool_ctx.settings.keyset);
    fclose(keyfile);
  }

  // Titlekey-Setup
  parse_hex_key(nca_ctx.tool_ctx->settings.cli_titlekey, titlekey, 16);
  nca_ctx.tool_ctx->settings.has_cli_titlekey = 1;

  // Base NCA-Setup
  if (nca_ctx.tool_ctx->base_file != NULL)
  {
    return EXIT_FAILURE;
  }
  if ((nca_ctx.tool_ctx->base_file = fopen(base_nca, "rb")) == NULL)
  {
    fprintf(stderr, "unable to open %s: %s\n", base_nca, strerror(errno));
    return EXIT_FAILURE;
  }
  nca_ctx.tool_ctx->base_file_type = BASEFILE_NCA;
  nca_ctx.tool_ctx->base_nca_ctx =
      malloc(sizeof(*nca_ctx.tool_ctx->base_nca_ctx));
  if (nca_ctx.tool_ctx->base_nca_ctx == NULL)
  {
    fprintf(stderr, "Failed to allocate base NCA context!\n");
    return EXIT_FAILURE;
  }
  nca_init(nca_ctx.tool_ctx->base_nca_ctx);
  base_ctx.file = nca_ctx.tool_ctx->base_file;
  nca_ctx.tool_ctx->base_nca_ctx->file = base_ctx.file;
  nca_ctx.tool_ctx->base_nca_ctx->is_cli_target = false;

  // Open Patch-NCA-File
  if ((tool_ctx.file = fopen(update_nca, "rb")) == NULL &&
      tool_ctx.file_type != FILETYPE_BOOT0)
  {
    fprintf(stderr, "unable to open %s: %s\n", update_nca, strerror(errno));
    return EXIT_FAILURE;
  }

  // Process NCA-File
  switch (tool_ctx.file_type)
  {
  case FILETYPE_NCA:
  {
    if (nca_ctx.tool_ctx->base_nca_ctx != NULL)
    {
      memcpy(&base_ctx.settings.keyset, &tool_ctx.settings.keyset,
             sizeof(nca_keyset_t));
      base_ctx.settings.known_titlekeys = tool_ctx.settings.known_titlekeys;
      nca_ctx.tool_ctx->base_nca_ctx->tool_ctx = &base_ctx;
      nca_process(nca_ctx.tool_ctx->base_nca_ctx);
      int found_romfs = 0;
      for (unsigned int i = 0; i < 4; i++)
      {
        if (nca_ctx.tool_ctx->base_nca_ctx->section_contexts[i].is_present &&
            nca_ctx.tool_ctx->base_nca_ctx->section_contexts[i].type == ROMFS)
        {
          found_romfs = 1;
          break;
        }
      }
      if (found_romfs == 0)
      {
        fprintf(stderr, "Unable to locate RomFS in base NCA!\n");
        return EXIT_FAILURE;
      }
    }

    nca_ctx.file = tool_ctx.file;
    nca_process(&nca_ctx);
    nca_free_section_contexts(&nca_ctx);

    if (nca_ctx.tool_ctx->base_file_type == BASEFILE_FAKE)
    {
      nca_ctx.tool_ctx->base_file = NULL;
    }

    if (nca_ctx.tool_ctx->base_file != NULL)
    {
      fclose(nca_ctx.tool_ctx->base_file);
      if (nca_ctx.tool_ctx->base_file_type == BASEFILE_NCA)
      {
        nca_free_section_contexts(nca_ctx.tool_ctx->base_nca_ctx);
        free(nca_ctx.tool_ctx->base_nca_ctx);
      }
    }
    break;
  }
  default:
  {
    fprintf(stderr, "Unknown File Type!\n\n");
  }
  }

  if (tool_ctx.settings.known_titlekeys.titlekeys != NULL)
  {
    free(tool_ctx.settings.known_titlekeys.titlekeys);
  }

  if (tool_ctx.file != NULL)
  {
    fclose(tool_ctx.file);
  }
  printf("Done!\n");

  return EXIT_SUCCESS;
}

__declspec(dllexport) NCAInfo nca_info(const char *nca, const char *prodkeys)
{
  hactool_ctx_t tool_ctx;
  nca_ctx_t nca_ctx;
  filepath_t keypath;
  NCAInfo info;

  nca_init(&nca_ctx);
  memset(&tool_ctx, 0, sizeof(tool_ctx));
  filepath_init(&keypath);
  nca_ctx.tool_ctx = &tool_ctx;
  nca_ctx.is_cli_target = true;

  // General-Setup
  nca_ctx.tool_ctx->file_type = FILETYPE_NCA;
  nca_ctx.tool_ctx->action = ACTION_INFO;
  nca_ctx.tool_ctx->settings.skip_key_warnings = 1;

  // Prodkeys-Setup
  pki_initialize_keyset(&tool_ctx.settings.keyset, KEYSET_RETAIL);
  filepath_set(&keypath, prodkeys);

  FILE *keyfile = NULL;
  if (keypath.valid == VALIDITY_VALID)
  {
    keyfile = os_fopen(keypath.os_path, OS_MODE_READ);
  }

  if (keyfile != NULL)
  {
    extkeys_initialize_settings(&tool_ctx.settings, keyfile);
    if (tool_ctx.settings.has_sdseed)
    {
      for (unsigned int key = 0; key < 2; key++)
      {
        for (unsigned int i = 0; i < 0x20; i++)
        {
          tool_ctx.settings.keyset.sd_card_key_sources[key][i] ^=
              tool_ctx.settings.sdseed[i & 0xF];
        }
      }
    }
    pki_derive_keys(&tool_ctx.settings.keyset);
    fclose(keyfile);
  }

  // Open Patch-NCA-File
  if ((tool_ctx.file = fopen(nca, "rb")) == NULL &&
      tool_ctx.file_type != FILETYPE_BOOT0)
  {
    fprintf(stderr, "unable to open %s: %s\n", nca, strerror(errno));
    info.status = EXIT_FAILURE;
    return info;
  }

  // Process NCA-File
  switch (tool_ctx.file_type)
  {
  case FILETYPE_NCA:
  {
    nca_ctx.file = tool_ctx.file;
    nca_process(&nca_ctx);
    nca_free_section_contexts(&nca_ctx);
    break;
  }
  default:
  {
    fprintf(stderr, "Unknown File Type!\n\n");
  }
  }

  if (tool_ctx.settings.known_titlekeys.titlekeys != NULL)
  {
    free(tool_ctx.settings.known_titlekeys.titlekeys);
  }

  if (tool_ctx.file != NULL)
  {
    fclose(tool_ctx.file);
  }
  printf("Done!\n");

  info.content_size = nca_ctx.header.nca_size;
  info.title_id = nca_ctx.header.title_id;
  sprintf(info.sdk_version, "%d.%d.%d.%d", nca_ctx.header.sdk_major,
          nca_ctx.header.sdk_minor, nca_ctx.header.sdk_micro,
          nca_ctx.header.sdk_revision);
  info.distrubution_type = nca_get_distribution_type(&nca_ctx);
  info.content_type = nca_get_content_type(&nca_ctx);
  sprintf(info.master_key_rev, "%d (%s)", nca_ctx.crypto_type,
          get_key_revision_summary(nca_ctx.crypto_type));

  return info;
}