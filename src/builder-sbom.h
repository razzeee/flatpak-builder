/* builder-sbom.h
 *
 * Copyright © 2026 flatpak-builder contributors
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef __BUILDER_SBOM_H__
#define __BUILDER_SBOM_H__

#include "builder-context.h"
#include "builder-manifest.h"

G_BEGIN_DECLS

gboolean builder_sbom_embed (BuilderManifest *manifest,
                             BuilderContext  *context,
                             const char      *manifest_sha256,
                             GError         **error);

gboolean builder_sbom_write_side_artifact (BuilderManifest *manifest,
                                           BuilderContext  *context,
                                           const char      *repo_path,
                                           const char      *output_dir,
                                           const char      *manifest_sha256,
                                           GError         **error);

G_END_DECLS

#endif /* __BUILDER_SBOM_H__ */
