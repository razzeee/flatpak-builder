/* builder-sbom.c
 *
 * Copyright © 2026 flatpak-builder contributors
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "config.h"

#include "builder-sbom.h"
#include "builder-flatpak-utils.h"
#include "builder-module.h"
#include "builder-source.h"

#include <ostree.h>

static char *
get_artifact_ref (BuilderManifest *manifest,
                  BuilderContext  *context)
{
  return flatpak_compose_ref (!builder_manifest_get_build_runtime (manifest) &&
                              !builder_manifest_get_build_extension (manifest),
                              builder_manifest_get_id (manifest),
                              builder_manifest_get_branch (manifest, context),
                              builder_context_get_arch (context));
}

static const char *
get_artifact_kind (BuilderManifest *manifest)
{
  if (builder_manifest_get_build_extension (manifest))
    return "extension";

  if (builder_manifest_get_build_runtime (manifest))
    return "runtime";

  return "app";
}

static void
add_property (JsonBuilder *builder,
              const char  *name,
              const char  *value)
{
  if (value == NULL)
    return;

  json_builder_begin_object (builder);
  json_builder_set_member_name (builder, "name");
  json_builder_add_string_value (builder, name);
  json_builder_set_member_name (builder, "value");
  json_builder_add_string_value (builder, value);
  json_builder_end_object (builder);
}

static void
add_component_property_array (JsonBuilder *builder,
                              BuilderManifest *manifest,
                              BuilderContext  *context,
                              const char      *manifest_sha256,
                              const char      *commit)
{
  g_autofree char *ref = get_artifact_ref (manifest, context);
  g_autofree char *runtime = NULL;
  g_autofree char *runtime_version = NULL;
  g_autofree char *runtime_commit = NULL;
  g_autofree char *sdk = NULL;
  g_autofree char *sdk_commit = NULL;

  g_object_get (manifest,
                "runtime", &runtime,
                "runtime-version", &runtime_version,
                "runtime-commit", &runtime_commit,
                "sdk", &sdk,
                "sdk-commit", &sdk_commit,
                NULL);

  json_builder_set_member_name (builder, "properties");
  json_builder_begin_array (builder);
  add_property (builder, "flatpak:kind", get_artifact_kind (manifest));
  add_property (builder, "flatpak:id", builder_manifest_get_id (manifest));
  add_property (builder, "flatpak:branch", builder_manifest_get_branch (manifest, context));
  add_property (builder, "flatpak:arch", builder_context_get_arch (context));
  add_property (builder, "flatpak:ref", ref);
  add_property (builder, "flatpak:commit", commit);
  add_property (builder, "flatpak:runtime", runtime);
  add_property (builder, "flatpak:runtime-version", runtime_version);
  add_property (builder, "flatpak:runtime-commit", runtime_commit);
  add_property (builder, "flatpak:sdk", sdk);
  add_property (builder, "flatpak:sdk-commit", sdk_commit);
  add_property (builder, "flatpak:manifest-sha256", manifest_sha256);
  json_builder_end_array (builder);
}

static void
add_external_reference (JsonBuilder *builder,
                        const char  *type,
                        const char  *url)
{
  if (url == NULL || *url == 0)
    return;

  json_builder_begin_object (builder);
  json_builder_set_member_name (builder, "type");
  json_builder_add_string_value (builder, type);
  json_builder_set_member_name (builder, "url");
  json_builder_add_string_value (builder, url);
  json_builder_end_object (builder);
}

static const char *
json_object_get_string_member_or_null (JsonObject  *object,
                                       const char  *name)
{
  if (!json_object_has_member (object, name))
    return NULL;

  return json_object_get_string_member (object, name);
}

static void
add_source_component (JsonBuilder   *builder,
                      BuilderSource *source,
                      const char    *module_name,
                      guint          source_index)
{
  g_autoptr(JsonNode) source_node = builder_source_to_json (source);
  JsonObject *object = json_node_get_object (source_node);
  const char *type = json_object_get_string_member_or_null (object, "type");
  const char *url = json_object_get_string_member_or_null (object, "url");
  const char *sha256 = json_object_get_string_member_or_null (object, "sha256");
  const char *commit = json_object_get_string_member_or_null (object, "commit");
  const char *branch = json_object_get_string_member_or_null (object, "branch");
  const char *tag = json_object_get_string_member_or_null (object, "tag");
  g_autofree char *bom_ref = g_strdup_printf ("flatpak:module:%s:source:%u", module_name, source_index);
  g_autofree char *name = NULL;

  if (url != NULL)
    name = g_path_get_basename (url);
  else
    name = g_strdup_printf ("%s-source-%u", module_name, source_index);

  json_builder_begin_object (builder);
  json_builder_set_member_name (builder, "type");
  json_builder_add_string_value (builder, "file");
  json_builder_set_member_name (builder, "bom-ref");
  json_builder_add_string_value (builder, bom_ref);
  json_builder_set_member_name (builder, "name");
  json_builder_add_string_value (builder, name);
  json_builder_set_member_name (builder, "scope");
  json_builder_add_string_value (builder, "required");

  if (sha256 != NULL)
    {
      json_builder_set_member_name (builder, "hashes");
      json_builder_begin_array (builder);
      json_builder_begin_object (builder);
      json_builder_set_member_name (builder, "alg");
      json_builder_add_string_value (builder, "SHA-256");
      json_builder_set_member_name (builder, "content");
      json_builder_add_string_value (builder, sha256);
      json_builder_end_object (builder);
      json_builder_end_array (builder);
    }

  if (url != NULL)
    {
      json_builder_set_member_name (builder, "externalReferences");
      json_builder_begin_array (builder);
      add_external_reference (builder, "distribution", url);
      json_builder_end_array (builder);
    }

  json_builder_set_member_name (builder, "properties");
  json_builder_begin_array (builder);
  add_property (builder, "flatpak:source-type", type);
  add_property (builder, "flatpak:source-url", url);
  add_property (builder, "flatpak:source-commit", commit);
  add_property (builder, "flatpak:source-branch", branch);
  add_property (builder, "flatpak:source-tag", tag);
  json_builder_end_array (builder);

  json_builder_end_object (builder);
}

static void
add_module_components (JsonBuilder *builder,
                       GList       *modules)
{
  for (GList *l = modules; l != NULL; l = l->next)
    {
      BuilderModule *module = l->data;
      const char *module_name = builder_module_get_name (module);
      GList *sources = builder_module_get_sources (module);
      guint source_index = 0;

      if (module_name == NULL)
        module_name = "unnamed";

      json_builder_begin_object (builder);
      json_builder_set_member_name (builder, "type");
      json_builder_add_string_value (builder, "library");
      json_builder_set_member_name (builder, "bom-ref");
      g_autofree char *module_bom_ref = g_strdup_printf ("flatpak:module:%s", module_name);
      json_builder_add_string_value (builder, module_bom_ref);
      json_builder_set_member_name (builder, "name");
      json_builder_add_string_value (builder, module_name);
      json_builder_set_member_name (builder, "scope");
      json_builder_add_string_value (builder, "required");
      json_builder_set_member_name (builder, "properties");
      json_builder_begin_array (builder);
      add_property (builder, "flatpak:component-kind", "manifest-module");
      json_builder_end_array (builder);
      json_builder_end_object (builder);

      for (GList *s = sources; s != NULL; s = s->next)
        add_source_component (builder, BUILDER_SOURCE (s->data), module_name, source_index++);

      add_module_components (builder, builder_module_get_modules (module));
    }
}

static void
add_dependency (JsonBuilder *builder,
                const char  *ref,
                GPtrArray   *depends_on)
{
  json_builder_begin_object (builder);
  json_builder_set_member_name (builder, "ref");
  json_builder_add_string_value (builder, ref);
  json_builder_set_member_name (builder, "dependsOn");
  json_builder_begin_array (builder);
  for (guint i = 0; i < depends_on->len; i++)
    json_builder_add_string_value (builder, g_ptr_array_index (depends_on, i));
  json_builder_end_array (builder);
  json_builder_end_object (builder);
}

static char *
generate_sbom_json (BuilderManifest *manifest,
                    BuilderContext  *context,
                    const char      *manifest_sha256,
                    const char      *commit,
                    GError         **error)
{
  g_autoptr(JsonBuilder) builder = json_builder_new ();
  g_autoptr(JsonGenerator) generator = NULL;
  g_autoptr(JsonNode) root = NULL;
  g_autoptr(GDateTime) now = g_date_time_new_now_utc ();
  g_autofree char *timestamp = g_date_time_format_iso8601 (now);
  g_autofree char *uuid = g_uuid_string_random ();
  g_autofree char *serial = g_strdup_printf ("urn:uuid:%s", uuid);
  g_autofree char *ref = get_artifact_ref (manifest, context);
  g_autofree char *artifact_bom_ref = g_strdup_printf ("flatpak:%s@%s", ref, commit);
  g_autofree char *purl = g_strdup_printf ("pkg:flatpak/%s@%s?arch=%s&branch=%s",
                                           builder_manifest_get_id (manifest),
                                           commit,
                                           builder_context_get_arch (context),
                                           builder_manifest_get_branch (manifest, context));
  g_autoptr(GPtrArray) root_depends = g_ptr_array_new_with_free_func (g_free);

  if (builder_manifest_get_id (manifest) == NULL ||
      builder_manifest_get_branch (manifest, context) == NULL ||
      builder_context_get_arch (context) == NULL ||
      commit == NULL)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Missing required Flatpak identity fields for SBOM");
      return NULL;
    }

  json_builder_begin_object (builder);
  json_builder_set_member_name (builder, "bomFormat");
  json_builder_add_string_value (builder, "CycloneDX");
  json_builder_set_member_name (builder, "specVersion");
  json_builder_add_string_value (builder, "1.7");
  json_builder_set_member_name (builder, "serialNumber");
  json_builder_add_string_value (builder, serial);
  json_builder_set_member_name (builder, "version");
  json_builder_add_int_value (builder, 1);

  json_builder_set_member_name (builder, "metadata");
  json_builder_begin_object (builder);
  json_builder_set_member_name (builder, "timestamp");
  json_builder_add_string_value (builder, timestamp);
  json_builder_set_member_name (builder, "tools");
  json_builder_begin_object (builder);
  json_builder_set_member_name (builder, "components");
  json_builder_begin_array (builder);
  json_builder_begin_object (builder);
  json_builder_set_member_name (builder, "type");
  json_builder_add_string_value (builder, "application");
  json_builder_set_member_name (builder, "name");
  json_builder_add_string_value (builder, "flatpak-builder");
  json_builder_set_member_name (builder, "version");
  json_builder_add_string_value (builder, PACKAGE_VERSION);
  json_builder_end_object (builder);
  json_builder_end_array (builder);
  json_builder_end_object (builder);

  json_builder_set_member_name (builder, "component");
  json_builder_begin_object (builder);
  json_builder_set_member_name (builder, "type");
  json_builder_add_string_value (builder, "application");
  json_builder_set_member_name (builder, "bom-ref");
  json_builder_add_string_value (builder, artifact_bom_ref);
  json_builder_set_member_name (builder, "name");
  json_builder_add_string_value (builder, builder_manifest_get_id (manifest));
  json_builder_set_member_name (builder, "version");
  json_builder_add_string_value (builder, builder_manifest_get_branch (manifest, context));
  json_builder_set_member_name (builder, "purl");
  json_builder_add_string_value (builder, purl);
  add_component_property_array (builder, manifest, context, manifest_sha256, commit);
  json_builder_end_object (builder);
  json_builder_end_object (builder);

  json_builder_set_member_name (builder, "components");
  json_builder_begin_array (builder);
  for (GList *l = builder_manifest_get_modules (manifest); l != NULL; l = l->next)
    {
      BuilderModule *module = l->data;
      const char *module_name = builder_module_get_name (module);

      if (module_name != NULL)
        g_ptr_array_add (root_depends, g_strdup_printf ("flatpak:module:%s", module_name));
    }
  add_module_components (builder, builder_manifest_get_modules (manifest));
  json_builder_end_array (builder);

  json_builder_set_member_name (builder, "dependencies");
  json_builder_begin_array (builder);
  add_dependency (builder, artifact_bom_ref, root_depends);
  json_builder_end_array (builder);

  json_builder_set_member_name (builder, "compositions");
  json_builder_begin_array (builder);
  json_builder_begin_object (builder);
  json_builder_set_member_name (builder, "aggregate");
  json_builder_add_string_value (builder, "incomplete");
  json_builder_set_member_name (builder, "assemblies");
  json_builder_begin_array (builder);
  json_builder_add_string_value (builder, artifact_bom_ref);
  json_builder_end_array (builder);
  json_builder_set_member_name (builder, "properties");
  json_builder_begin_array (builder);
  add_property (builder, "flatpak:manifest-modules", "complete");
  add_property (builder, "flatpak:post-build-inventory", "incomplete");
  json_builder_end_array (builder);
  json_builder_end_object (builder);
  json_builder_end_array (builder);

  json_builder_end_object (builder);

  root = json_builder_get_root (builder);
  generator = json_generator_new ();
  json_generator_set_pretty (generator, TRUE);
  json_generator_set_root (generator, root);

  return json_generator_to_data (generator, NULL);
}

static gboolean
validate_generated_json (const char *json,
                         GError    **error)
{
  g_autoptr(JsonParser) parser = json_parser_new ();

  if (!json_parser_load_from_data (parser, json, -1, error))
    {
      g_prefix_error (error, "Generated invalid CycloneDX JSON: ");
      return FALSE;
    }

  return TRUE;
}

static gboolean
write_sbom_file (GFile       *file,
                 const char  *json,
                 GError     **error)
{
  g_autoptr(GFile) parent = g_file_get_parent (file);
  g_autoptr(GError) local_error = NULL;

  if (!g_file_make_directory_with_parents (parent, NULL, &local_error) &&
      !g_error_matches (local_error, G_IO_ERROR, G_IO_ERROR_EXISTS))
    {
      g_propagate_error (error, g_steal_pointer (&local_error));
      return FALSE;
    }

  return g_file_replace_contents (file, json, strlen (json), NULL, FALSE,
                                  G_FILE_CREATE_REPLACE_DESTINATION, NULL, NULL, error);
}

gboolean
builder_sbom_embed (BuilderManifest *manifest,
                    BuilderContext  *context,
                    const char      *manifest_sha256,
                    GError         **error)
{
  GFile *app_dir = builder_context_get_app_dir (context);
  g_autoptr(GFile) sbom_file = NULL;
  g_autofree char *json = NULL;
  g_autofree char *relative_path = NULL;
  g_autofree char *filename = g_strdup_printf ("%s.cdx.json", builder_manifest_get_id (manifest));

  relative_path = g_build_filename (builder_manifest_get_build_runtime (manifest) ? "usr" : "files",
                                    "share", "sbom", filename, NULL);
  sbom_file = g_file_resolve_relative_path (app_dir, relative_path);

  json = generate_sbom_json (manifest, context, manifest_sha256, "unknown", error);
  if (json == NULL)
    return FALSE;

  if (!validate_generated_json (json, error))
    return FALSE;

  if (!write_sbom_file (sbom_file, json, error))
    {
      g_prefix_error (error, "Cannot embed SBOM into artifact: ");
      return FALSE;
    }

  return TRUE;
}

static char *
resolve_exported_commit (const char      *repo_path,
                         BuilderManifest *manifest,
                         BuilderContext  *context,
                         GError         **error)
{
  g_autoptr(GFile) repo_file = g_file_new_for_path (repo_path);
  g_autoptr(OstreeRepo) repo = ostree_repo_new (repo_file);
  g_autofree char *ref = get_artifact_ref (manifest, context);
  char *commit = NULL;

  if (!ostree_repo_open (repo, NULL, error))
    return NULL;

  if (!ostree_repo_resolve_rev (repo, ref, FALSE, &commit, error))
    return NULL;

  return commit;
}

gboolean
builder_sbom_write_side_artifact (BuilderManifest *manifest,
                                  BuilderContext  *context,
                                  const char      *repo_path,
                                  const char      *output_dir,
                                  const char      *manifest_sha256,
                                  GError         **error)
{
  g_autofree char *commit = NULL;
  g_autofree char *json = NULL;
  g_autofree char *filename = NULL;
  g_autoptr(GFile) output = NULL;
  g_autoptr(GFile) output_file = NULL;

  commit = resolve_exported_commit (repo_path, manifest, context, error);
  if (commit == NULL)
    return FALSE;

  json = generate_sbom_json (manifest, context, manifest_sha256, commit, error);
  if (json == NULL)
    return FALSE;

  if (!validate_generated_json (json, error))
    return FALSE;

  filename = g_strdup_printf ("%s@%s.cdx.json", builder_manifest_get_id (manifest), commit);
  output = g_file_new_for_path (output_dir);
  output_file = g_file_get_child (output, filename);

  if (!write_sbom_file (output_file, json, error))
    {
      g_prefix_error (error, "Cannot write SBOM side artifact: ");
      return FALSE;
    }

  return TRUE;
}
