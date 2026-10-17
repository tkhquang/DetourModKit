#ifndef DETOURMODKIT_STAGED_RELOAD_H
#define DETOURMODKIT_STAGED_RELOAD_H

/**
 * @file staged_reload.h
 * @brief Versioned C ABI values that a staged-reload logic image returns from its shutdown export.
 * @details A loader that hot-reloads a logic image calls the image's shutdown export and branches on the value. The
 *          loader and the image agree on the ABI version through their own protocol. A loader at ABI 2 knows only
 *          REFUSED, OK, and RETAINED, so an image that serves it returns REFUSED in place of BUSY or RESTART_REQUIRED.
 */

/** @brief ABI revision of these values. */
#define DMK_STAGED_RELOAD_ABI_VERSION 3u

/**
 * @name Shutdown results
 * @brief The values of the shutdown export. Each value is stable across every later revision.
 * @{
 */
#define DMK_STAGED_RELOAD_REFUSED 0u          /**< The image refused shutdown. The loader keeps it mapped. */
#define DMK_STAGED_RELOAD_OK 1u               /**< Every hook and resource retired. The loader can unmap the image. */
#define DMK_STAGED_RELOAD_RETAINED 2u         /**< The image keeps a resource that needs its code. Keep it mapped. */
#define DMK_STAGED_RELOAD_BUSY 3u             /**< A call stayed in flight and nothing changed. Retry the shutdown. */
#define DMK_STAGED_RELOAD_RESTART_REQUIRED 4u /**< A detour stays reachable. Keep the image and reload no more. */
/** @} */

#endif /* DETOURMODKIT_STAGED_RELOAD_H */
