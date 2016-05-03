
/* png.c - location for general purpose libpng functions
 *
 * Last changed in libpng 1.6.19 [November 12, 2015]
 * Copyright (c) 1998-2015 Glenn Randers-Pehrson
 * (Version 0.96 Copyright (c) 1996, 1997 Andreas Dilger)
 * (Version 0.88 Copyright (c) 1995, 1996 Guy Eric Schalnat, Group 42, Inc.)
 *
 * This code is released under the libpng license.
 * For conditions of distribution and use, see the disclaimer
 * and license in png.h
 */

#include "pngpriv.h"

/* Generate a compiler error if there is an old png.h in the search path. */
typedef png_libpng_version_1_6_20 Your_png_h_is_not_version_1_6_20;

/* Tells libpng that we have already handled the first "num_bytes" bytes
 * of the PNG file signature.  If the PNG data is embedded into another
 * stream we can set num_bytes = 8 so that libpng will not attempt to read
 * or write any of the magic bytes before it starts on the IHDR.
 */

#ifdef PNG_READ_SUPPORTED
void PNGAPI
png_set_sig_bytes(png_structrp png_ptr, int num_bytes)
{
   unsigned int nb = (unsigned int)num_bytes;

   png_debug(1, "in png_set_sig_bytes");

   if (png_ptr == NULL)
      return;

   if (num_bytes < 0)
      nb = 0;

   if (nb > 8)
      png_error(png_ptr, "Too many bytes for PNG signature");

   png_ptr->sig_bytes = (png_byte)nb;
}

/* Checks whether the supplied bytes match the PNG signature.  We allow
 * checking less than the full 8-byte signature so that those apps that
 * already read the first few bytes of a file to determine the file type
 * can simply check the remaining bytes for extra assurance.  Returns
 * an integer less than, equal to, or greater than zero if sig is found,
 * respectively, to be less than, to match, or be greater than the correct
 * PNG signature (this is the same behavior as strcmp, memcmp, etc).
 */
int PNGAPI
png_sig_cmp(png_const_bytep sig, png_size_t start, png_size_t num_to_check)
{
   png_byte png_signature[8] = {137, 80, 78, 71, 13, 10, 26, 10};

   if (num_to_check > 8)
      num_to_check = 8;

   else if (num_to_check < 1)
      return (-1);

   if (start > 7)
      return (-1);

   if (start + num_to_check > 8)
      num_to_check = 8 - start;

   return ((int)(memcmp(&sig[start], &png_signature[start], num_to_check)));
}

#endif /* READ */

#if defined(PNG_READ_SUPPORTED) || defined(PNG_WRITE_SUPPORTED)
/* Function to allocate memory for zlib */
PNG_FUNCTION(voidpf /* PRIVATE */,
png_zalloc,(voidpf png_ptr, uInt items, uInt size),PNG_ALLOCATED)
{
   png_alloc_size_t num_bytes = size;

   if (png_ptr == NULL)
      return NULL;

   if (items >= (~(png_alloc_size_t)0)/size)
   {
      png_warning (png_voidcast(png_structrp, png_ptr),
         "Potential overflow in png_zalloc()");
      return NULL;
   }

   num_bytes *= items;
   return png_malloc_warn(png_voidcast(png_structrp, png_ptr), num_bytes);
}

/* Function to free memory for zlib */
void /* PRIVATE */
png_zfree(voidpf png_ptr, voidpf ptr)
{
   png_free(png_voidcast(png_const_structrp,png_ptr), ptr);
}

/* Reset the CRC variable to 32 bits of 1's.  Care must be taken
 * in case CRC is > 32 bits to leave the top bits 0.
 */
void /* PRIVATE */
png_reset_crc(png_structrp png_ptr)
{
   /* The cast is safe because the crc is a 32-bit value. */
   png_ptr->crc = (png_uint_32)crc32(0, Z_NULL, 0);
}

/* Calculate the CRC over a section of data.  We can only pass as
 * much data to this routine as the largest single buffer size.  We
 * also check that this data will actually be used before going to the
 * trouble of calculating it.
 */
void /* PRIVATE */
png_calculate_crc(png_structrp png_ptr, png_const_bytep ptr, png_size_t length)
{
   int need_crc = 1;

   if (PNG_CHUNK_ANCILLARY(png_ptr->chunk_name) != 0)
   {
      if ((png_ptr->flags & PNG_FLAG_CRC_ANCILLARY_MASK) ==
          (PNG_FLAG_CRC_ANCILLARY_USE | PNG_FLAG_CRC_ANCILLARY_NOWARN))
         need_crc = 0;
   }

   else /* critical */
   {
      if ((png_ptr->flags & PNG_FLAG_CRC_CRITICAL_IGNORE) != 0)
         need_crc = 0;
   }

   /* 'uLong' is defined in zlib.h as unsigned long; this means that on some
    * systems it is a 64-bit value.  crc32, however, returns 32 bits so the
    * following cast is safe.  'uInt' may be no more than 16 bits, so it is
    * necessary to perform a loop here.
    */
   if (need_crc != 0 && length > 0)
   {
      uLong crc = png_ptr->crc; /* Should never issue a warning */

      do
      {
         uInt safe_length = (uInt)length;
#ifndef __COVERITY__
         if (safe_length == 0)
            safe_length = (uInt)-1; /* evil, but safe */
#endif

         crc = crc32(crc, ptr, safe_length);

         /* The following should never issue compiler warnings; if they do the
          * target system has characteristics that will probably violate other
          * assumptions within the libpng code.
          */
         ptr += safe_length;
         length -= safe_length;
      }
      while (length > 0);

      /* And the following is always safe because the crc is only 32 bits. */
      png_ptr->crc = (png_uint_32)crc;
   }
}

/* Check a user supplied version number, called from both read and write
 * functions that create a png_struct.
 */
int
png_user_version_check(png_structrp png_ptr, png_const_charp user_png_ver)
{
     /* Libpng versions 1.0.0 and later are binary compatible if the version
      * string matches through the second '.'; we must recompile any
      * applications that use any older library version.
      */

   if (user_png_ver != NULL)
   {
      int i = -1;
      int found_dots = 0;

      do
      {
         i++;
         if (user_png_ver[i] != PNG_LIBPNG_VER_STRING[i])
            png_ptr->flags |= PNG_FLAG_LIBRARY_MISMATCH;
         if (user_png_ver[i] == '.')
            found_dots++;
      } while (found_dots < 2 && user_png_ver[i] != 0 &&
            PNG_LIBPNG_VER_STRING[i] != 0);
   }

   else
      png_ptr->flags |= PNG_FLAG_LIBRARY_MISMATCH;

   if ((png_ptr->flags & PNG_FLAG_LIBRARY_MISMATCH) != 0)
   {
#ifdef PNG_WARNINGS_SUPPORTED
      size_t pos = 0;
      char m[128];

      pos = png_safecat(m, (sizeof m), pos,
          "Application built with libpng-");
      pos = png_safecat(m, (sizeof m), pos, user_png_ver);
      pos = png_safecat(m, (sizeof m), pos, " but running with ");
      pos = png_safecat(m, (sizeof m), pos, PNG_LIBPNG_VER_STRING);
      PNG_UNUSED(pos)

      png_warning(png_ptr, m);
#endif

#ifdef PNG_ERROR_NUMBERS_SUPPORTED
      png_ptr->flags = 0;
#endif

      return 0;
   }

   /* Success return. */
   return 1;
}

/* Generic function to create a png_struct for either read or write - this
 * contains the common initialization.
 */
PNG_FUNCTION(png_structp /* PRIVATE */,
png_create_png_struct,(png_const_charp user_png_ver, png_voidp error_ptr,
    png_error_ptr error_fn, png_error_ptr warn_fn, png_voidp mem_ptr,
    png_malloc_ptr malloc_fn, png_free_ptr free_fn),PNG_ALLOCATED)
{
   png_struct create_struct;
#  ifdef PNG_SETJMP_SUPPORTED
      jmp_buf create_jmp_buf;
#  endif

   /* This temporary stack-allocated structure is used to provide a place to
    * build enough context to allow the user provided memory allocator (if any)
    * to be called.
    */
   memset(&create_struct, 0, (sizeof create_struct));

   /* Added at libpng-1.2.6 */
#  ifdef PNG_USER_LIMITS_SUPPORTED
      create_struct.user_width_max = PNG_USER_WIDTH_MAX;
      create_struct.user_height_max = PNG_USER_HEIGHT_MAX;

#     ifdef PNG_USER_CHUNK_CACHE_MAX
      /* Added at libpng-1.2.43 and 1.4.0 */
      create_struct.user_chunk_cache_max = PNG_USER_CHUNK_CACHE_MAX;
#     endif

#     ifdef PNG_USER_CHUNK_MALLOC_MAX
      /* Added at libpng-1.2.43 and 1.4.1, required only for read but exists
       * in png_struct regardless.
       */
      create_struct.user_chunk_malloc_max = PNG_USER_CHUNK_MALLOC_MAX;
#     endif
#  endif

   /* The following two API calls simply set fields in png_struct, so it is safe
    * to do them now even though error handling is not yet set up.
    */
#  ifdef PNG_USER_MEM_SUPPORTED
      png_set_mem_fn(&create_struct, mem_ptr, malloc_fn, free_fn);
#  else
      PNG_UNUSED(mem_ptr)
      PNG_UNUSED(malloc_fn)
      PNG_UNUSED(free_fn)
#  endif

   /* (*error_fn) can return control to the caller after the error_ptr is set,
    * this will result in a memory leak unless the error_fn does something
    * extremely sophisticated.  The design lacks merit but is implicit in the
    * API.
    */
   png_set_error_fn(&create_struct, error_ptr, error_fn, warn_fn);

#  ifdef PNG_SETJMP_SUPPORTED
      if (!setjmp(create_jmp_buf))
#  endif
      {
#  ifdef PNG_SETJMP_SUPPORTED
         /* Temporarily fake out the longjmp information until we have
          * successfully completed this function.  This only works if we have
          * setjmp() support compiled in, but it is safe - this stuff should
          * never happen.
          */
         create_struct.jmp_buf_ptr = &create_jmp_buf;
         create_struct.jmp_buf_size = 0; /*stack allocation*/
         create_struct.longjmp_fn = longjmp;
#  endif
         /* Call the general version checker (shared with read and write code):
          */
         if (png_user_version_check(&create_struct, user_png_ver) != 0)
         {
            png_structrp png_ptr = png_voidcast(png_structrp,
               png_malloc_warn(&create_struct, (sizeof *png_ptr)));

            if (png_ptr != NULL)
            {
               /* png_ptr->zstream holds a back-pointer to the png_struct, so
                * this can only be done now:
                */
               create_struct.zstream.zalloc = png_zalloc;
               create_struct.zstream.zfree = png_zfree;
               create_struct.zstream.opaque = png_ptr;

#              ifdef PNG_SETJMP_SUPPORTED
               /* Eliminate the local error handling: */
               create_struct.jmp_buf_ptr = NULL;
               create_struct.jmp_buf_size = 0;
               create_struct.longjmp_fn = 0;
#              endif

               *png_ptr = create_struct;

               /* This is the successful return point */
               return png_ptr;
            }
         }
      }

   /* A longjmp because of a bug in the application storage allocator or a
    * simple failure to allocate the png_struct.
    */
   return NULL;
}

/* Allocate the memory for an info_struct for the application. */
PNG_FUNCTION(png_infop,PNGAPI
png_create_info_struct,(png_const_structrp png_ptr),PNG_ALLOCATED)
{
   png_inforp info_ptr;

   png_debug(1, "in png_create_info_struct");

   if (png_ptr == NULL)
      return NULL;

   /* Use the internal API that does not (or at least should not) error out, so
    * that this call always returns ok.  The application typically sets up the
    * error handling *after* creating the info_struct because this is the way it
    * has always been done in 'example.c'.
    */
   info_ptr = png_voidcast(png_inforp, png_malloc_base(png_ptr,
      (sizeof *info_ptr)));

   if (info_ptr != NULL)
      memset(info_ptr, 0, (sizeof *info_ptr));

   return info_ptr;
}

/* This function frees the memory associated with a single info struct.
 * Normally, one would use either png_destroy_read_struct() or
 * png_destroy_write_struct() to free an info struct, but this may be
 * useful for some applications.  From libpng 1.6.0 this function is also used
 * internally to implement the png_info release part of the 'struct' destroy
 * APIs.  This ensures that all possible approaches free the same data (all of
 * it).
 */
void PNGAPI
png_destroy_info_struct(png_const_structrp png_ptr, png_infopp info_ptr_ptr)
{
   png_inforp info_ptr = NULL;

   png_debug(1, "in png_destroy_info_struct");

   if (png_ptr == NULL)
      return;

   if (info_ptr_ptr != NULL)
      info_ptr = *info_ptr_ptr;

   if (info_ptr != NULL)
   {
      /* Do this first in case of an error below; if the app implements its own
       * memory management this can lead to png_free calling png_error, which
       * will abort this routine and return control to the app error handler.
       * An infinite loop may result if it then tries to free the same info
       * ptr.
       */
      *info_ptr_ptr = NULL;

      png_free_data(png_ptr, info_ptr, PNG_FREE_ALL, -1);
      memset(info_ptr, 0, (sizeof *info_ptr));
      png_free(png_ptr, info_ptr);
   }
}

/* Initialize the info structure.  This is now an internal function (0.89)
 * and applications using it are urged to use png_create_info_struct()
 * instead.  Use deprecated in 1.6.0, internal use removed (used internally it
 * is just a memset).
 *
 * NOTE: it is almost inconceivable that this API is used because it bypasses
 * the user-memory mechanism and the user error handling/warning mechanisms in
 * those cases where it does anything other than a memset.
 */
PNG_FUNCTION(void,PNGAPI
png_info_init_3,(png_infopp ptr_ptr, png_size_t png_info_struct_size),
   PNG_DEPRECATED)
{
   png_inforp info_ptr = *ptr_ptr;

   png_debug(1, "in png_info_init_3");

   if (info_ptr == NULL)
      return;

   if ((sizeof (png_info)) > png_info_struct_size)
   {
      *ptr_ptr = NULL;
      /* The following line is why this API should not be used: */
      free(info_ptr);
      info_ptr = png_voidcast(png_inforp, png_malloc_base(NULL,
         (sizeof *info_ptr)));
      if (info_ptr == NULL)
         return;
      *ptr_ptr = info_ptr;
   }

   /* Set everything to 0 */
   memset(info_ptr, 0, (sizeof *info_ptr));
}

/* The following API is not called internally */
void PNGAPI
png_data_freer(png_const_structrp png_ptr, png_inforp info_ptr,
   int freer, png_uint_32 mask)
{
   png_debug(1, "in png_data_freer");

   if (png_ptr == NULL || info_ptr == NULL)
      return;

   if (freer == PNG_DESTROY_WILL_FREE_DATA)
      info_ptr->free_me |= mask;

   else if (freer == PNG_USER_WILL_FREE_DATA)
      info_ptr->free_me &= ~mask;

   else
      png_error(png_ptr, "Unknown freer parameter in png_data_freer");
}

void PNGAPI
png_free_data(png_const_structrp png_ptr, png_inforp info_ptr, png_uint_32 mask,
   int num)
{
   png_debug(1, "in png_free_data");

   if (png_ptr == NULL || info_ptr == NULL)
      return;

#ifdef PNG_TEXT_SUPPORTED
   /* Free text item num or (if num == -1) all text items */
   if (info_ptr->text != 0 &&
       ((mask & PNG_FREE_TEXT) & info_ptr->free_me) != 0)
   {
      if (num != -1)
      {
         png_free(png_ptr, info_ptr->text[num].key);
         info_ptr->text[num].key = NULL;
      }

      else
      {
         int i;

         for (i = 0; i < info_ptr->num_text; i++)
            png_free(png_ptr, info_ptr->text[i].key);

         png_free(png_ptr, info_ptr->text);
         info_ptr->text = NULL;
         info_ptr->num_text = 0;
      }
   }
#endif

#ifdef PNG_tRNS_SUPPORTED
   /* Free any tRNS entry */
   if (((mask & PNG_FREE_TRNS) & info_ptr->free_me) != 0)
   {
      info_ptr->valid &= ~PNG_INFO_tRNS;
      png_free(png_ptr, info_ptr->trans_alpha);
      info_ptr->trans_alpha = NULL;
      info_ptr->num_trans = 0;
   }
#endif

#ifdef PNG_sCAL_SUPPORTED
   /* Free any sCAL entry */
   if (((mask & PNG_FREE_SCAL) & info_ptr->free_me) != 0)
   {
      png_free(png_ptr, info_ptr->scal_s_width);
      png_free(png_ptr, info_ptr->scal_s_height);
      info_ptr->scal_s_width = NULL;
      info_ptr->scal_s_height = NULL;
      info_ptr->valid &= ~PNG_INFO_sCAL;
   }
#endif

#ifdef PNG_pCAL_SUPPORTED
   /* Free any pCAL entry */
   if (((mask & PNG_FREE_PCAL) & info_ptr->free_me) != 0)
   {
      png_free(png_ptr, info_ptr->pcal_purpose);
      png_free(png_ptr, info_ptr->pcal_units);
      info_ptr->pcal_purpose = NULL;
      info_ptr->pcal_units = NULL;

      if (info_ptr->pcal_params != NULL)
         {
            int i;

            for (i = 0; i < info_ptr->pcal_nparams; i++)
               png_free(png_ptr, info_ptr->pcal_params[i]);

            png_free(png_ptr, info_ptr->pcal_params);
            info_ptr->pcal_params = NULL;
         }
      info_ptr->valid &= ~PNG_INFO_pCAL;
   }
#endif

#ifdef PNG_iCCP_SUPPORTED
   /* Free any profile entry */
   if (((mask & PNG_FREE_ICCP) & info_ptr->free_me) != 0)
   {
      png_free(png_ptr, info_ptr->iccp_name);
      png_free(png_ptr, info_ptr->iccp_profile);
      info_ptr->iccp_name = NULL;
      info_ptr->iccp_profile = NULL;
      info_ptr->valid &= ~PNG_INFO_iCCP;
   }
#endif

#ifdef PNG_sPLT_SUPPORTED
   /* Free a given sPLT entry, or (if num == -1) all sPLT entries */
   if (info_ptr->splt_palettes != 0 &&
       ((mask & PNG_FREE_SPLT) & info_ptr->free_me) != 0)
   {
      if (num != -1)
      {
         png_free(png_ptr, info_ptr->splt_palettes[num].name);
         png_free(png_ptr, info_ptr->splt_palettes[num].entries);
         info_ptr->splt_palettes[num].name = NULL;
         info_ptr->splt_palettes[num].entries = NULL;
      }

      else
      {
         int i;

         for (i = 0; i < info_ptr->splt_palettes_num; i++)
         {
            png_free(png_ptr, info_ptr->splt_palettes[i].name);
            png_free(png_ptr, info_ptr->splt_palettes[i].entries);
         }

         png_free(png_ptr, info_ptr->splt_palettes);
         info_ptr->splt_palettes = NULL;
         info_ptr->splt_palettes_num = 0;
         info_ptr->valid &= ~PNG_INFO_sPLT;
      }
   }
#endif

#ifdef PNG_STORE_UNKNOWN_CHUNKS_SUPPORTED
   if (info_ptr->unknown_chunks != 0 &&
       ((mask & PNG_FREE_UNKN) & info_ptr->free_me) != 0)
   {
      if (num != -1)
      {
          png_free(png_ptr, info_ptr->unknown_chunks[num].data);
          info_ptr->unknown_chunks[num].data = NULL;
      }

      else
      {
         int i;

         for (i = 0; i < info_ptr->unknown_chunks_num; i++)
            png_free(png_ptr, info_ptr->unknown_chunks[i].data);

         png_free(png_ptr, info_ptr->unknown_chunks);
         info_ptr->unknown_chunks = NULL;
         info_ptr->unknown_chunks_num = 0;
      }
   }
#endif

#ifdef PNG_hIST_SUPPORTED
   /* Free any hIST entry */
   if (((mask & PNG_FREE_HIST) & info_ptr->free_me) != 0)
   {
      png_free(png_ptr, info_ptr->hist);
      info_ptr->hist = NULL;
      info_ptr->valid &= ~PNG_INFO_hIST;
   }
#endif

   /* Free any PLTE entry that was internally allocated */
   if (((mask & PNG_FREE_PLTE) & info_ptr->free_me) != 0)
   {
      png_free(png_ptr, info_ptr->palette);
      info_ptr->palette = NULL;
      info_ptr->valid &= ~PNG_INFO_PLTE;
      info_ptr->num_palette = 0;
   }

#ifdef PNG_INFO_IMAGE_SUPPORTED
   /* Free any image bits attached to the info structure */
   if (((mask & PNG_FREE_ROWS) & info_ptr->free_me) != 0)
   {
      if (info_ptr->row_pointers != 0)
      {
         png_uint_32 row;
         for (row = 0; row < info_ptr->height; row++)
            png_free(png_ptr, info_ptr->row_pointers[row]);

         png_free(png_ptr, info_ptr->row_pointers);
         info_ptr->row_pointers = NULL;
      }
      info_ptr->valid &= ~PNG_INFO_IDAT;
   }
#endif

   if (num != -1)
      mask &= ~PNG_FREE_MUL;

   info_ptr->free_me &= ~mask;
}
#endif /* READ || WRITE */

/* This function returns a pointer to the io_ptr associated with the user
 * functions.  The application should free any memory associated with this
 * pointer before png_write_destroy() or png_read_destroy() are called.
 */
png_voidp PNGAPI
png_get_io_ptr(png_const_structrp png_ptr)
{
   if (png_ptr == NULL)
      return (NULL);

   return (png_ptr->io_ptr);
}

#if defined(PNG_READ_SUPPORTED) || defined(PNG_WRITE_SUPPORTED)
#  ifdef PNG_STDIO_SUPPORTED
/* Initialize the default input/output functions for the PNG file.  If you
 * use your own read or write routines, you can call either png_set_read_fn()
 * or png_set_write_fn() instead of png_init_io().  If you have defined
 * PNG_NO_STDIO or otherwise disabled PNG_STDIO_SUPPORTED, you must use a
 * function of your own because "FILE *" isn't necessarily available.
 */
void PNGAPI
png_init_io(png_structrp png_ptr, png_FILE_p fp)
{
   png_debug(1, "in png_init_io");

   if (png_ptr == NULL)
      return;

   png_ptr->io_ptr = (png_voidp)fp;
}
#  endif

#  ifdef PNG_SAVE_INT_32_SUPPORTED
/* PNG signed integers are saved in 32-bit 2's complement format.  ANSI C-90
 * defines a cast of a signed integer to an unsigned integer either to preserve
 * the value, if it is positive, or to calculate:
 *
 *     (UNSIGNED_MAX+1) + integer
 *
 * Where UNSIGNED_MAX is the appropriate maximum unsigned value, so when the
 * negative integral value is added the result will be an unsigned value
 * correspnding to the 2's complement representation.
 */
void PNGAPI
png_save_int_32(png_bytep buf, png_int_32 i)
{
   png_save_uint_32(buf, i);
}
#  endif

#  ifdef PNG_TIME_RFC1123_SUPPORTED
/* Convert the supplied time into an RFC 1123 string suitable for use in
 * a "Creation Time" or other text-based time string.
 */
int PNGAPI
png_convert_to_rfc1123_buffer(char out[29], png_const_timep ptime)
{
   static PNG_CONST char short_months[12][4] =
        {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

   if (out == NULL)
      return 0;

   if (ptime->year > 9999 /* RFC1123 limitation */ ||
       ptime->month == 0    ||  ptime->month > 12  ||
       ptime->day   == 0    ||  ptime->day   > 31  ||
       ptime->hour  > 23    ||  ptime->minute > 59 ||
       ptime->second > 60)
      return 0;

   {
      size_t pos = 0;
      char number_buf[5]; /* enough for a four-digit year */

#     define APPEND_STRING(string) pos = png_safecat(out, 29, pos, (string))
#     define APPEND_NUMBER(format, value)\
         APPEND_STRING(PNG_FORMAT_NUMBER(number_buf, format, (value)))
#     define APPEND(ch) if (pos < 28) out[pos++] = (ch)

      APPEND_NUMBER(PNG_NUMBER_FORMAT_u, (unsigned)ptime->day);
      APPEND(' ');
      APPEND_STRING(short_months[(ptime->month - 1)]);
      APPEND(' ');
      APPEND_NUMBER(PNG_NUMBER_FORMAT_u, ptime->year);
      APPEND(' ');
      APPEND_NUMBER(PNG_NUMBER_FORMAT_02u, (unsigned)ptime->hour);
      APPEND(':');
      APPEND_NUMBER(PNG_NUMBER_FORMAT_02u, (unsigned)ptime->minute);
      APPEND(':');
      APPEND_NUMBER(PNG_NUMBER_FORMAT_02u, (unsigned)ptime->second);
      APPEND_STRING(" +0000"); /* This reliably terminates the buffer */
      PNG_UNUSED (pos)

#     undef APPEND
#     undef APPEND_NUMBER
#     undef APPEND_STRING
   }

   return 1;
}

#    if PNG_LIBPNG_VER < 10700
/* To do: remove the following from libpng-1.7 */
/* Original API that uses a private buffer in png_struct.
 * Deprecated because it causes png_struct to carry a spurious temporary
 * buffer (png_struct::time_buffer), better to have the caller pass this in.
 */
png_const_charp PNGAPI
png_convert_to_rfc1123(png_structrp png_ptr, png_const_timep ptime)
{
   if (png_ptr != NULL)
   {
      /* The only failure above if png_ptr != NULL is from an invalid ptime */
      if (png_convert_to_rfc1123_buffer(png_ptr->time_buffer, ptime) == 0)
         png_warning(png_ptr, "Ignoring invalid time value");

      else
         return png_ptr->time_buffer;
   }

   return NULL;
}
#    endif /* LIBPNG_VER < 10700 */
#  endif /* TIME_RFC1123 */

#endif /* READ || WRITE */

png_const_charp PNGAPI
png_get_copyright(png_const_structrp png_ptr)
{
   PNG_UNUSED(png_ptr)  /* Silence compiler warning about unused png_ptr */
#ifdef PNG_STRING_COPYRIGHT
   return PNG_STRING_COPYRIGHT
#else
#  ifdef __STDC__
   return PNG_STRING_NEWLINE \
      "libpng version 1.6.20 - December 3, 2015" PNG_STRING_NEWLINE \
      "Copyright (c) 1998-2015 Glenn Randers-Pehrson" PNG_STRING_NEWLINE \
      "Copyright (c) 1996-1997 Andreas Dilger" PNG_STRING_NEWLINE \
      "Copyright (c) 1995-1996 Guy Eric Schalnat, Group 42, Inc." \
      PNG_STRING_NEWLINE;
#  else
   return "libpng version 1.6.20 - December 3, 2015\
      Copyright (c) 1998-2015 Glenn Randers-Pehrson\
      Copyright (c) 1996-1997 Andreas Dilger\
      Copyright (c) 1995-1996 Guy Eric Schalnat, Group 42, Inc.";
#  endif
#endif
}

/* The following return the library version as a short string in the
 * format 1.0.0 through 99.99.99zz.  To get the version of *.h files
 * used with your application, print out PNG_LIBPNG_VER_STRING, which
 * is defined in png.h.
 * Note: now there is no difference between png_get_libpng_ver() and
 * png_get_header_ver().  Due to the version_nn_nn_nn typedef guard,
 * it is guaranteed that png.c uses the correct version of png.h.
 */
png_charp PNGAPI
png_get_libpng_ver(png_structp png_ptr)
{
   /* Version of *.c files used when building libpng */
   png_ptr = png_ptr;  /* Silence compiler warning about unused png_ptr */
   return ((png_charp) PNG_LIBPNG_VER_STRING);
}

png_charp PNGAPI
png_get_header_ver(png_structp png_ptr)
{
   /* Version of *.h files used when building libpng */
   png_ptr = png_ptr;  /* Silence compiler warning about unused png_ptr */
   return ((png_charp) PNG_LIBPNG_VER_STRING);
}

png_charp PNGAPI
png_get_header_version(png_structp png_ptr)
{
   /* Returns longer string containing both version and date */
   png_ptr = png_ptr;  /* Silence compiler warning about unused png_ptr */
#ifdef __STDC__
   return ((png_charp) PNG_HEADER_VERSION_STRING
#ifndef PNG_READ_SUPPORTED
   "     (NO READ SUPPORT)"
#endif
   PNG_STRING_NEWLINE);
#else
   return ((png_charp) PNG_HEADER_VERSION_STRING);
#endif
}

#if defined(PNG_READ_SUPPORTED) || defined(PNG_WRITE_SUPPORTED)
#ifdef PNG_HANDLE_AS_UNKNOWN_SUPPORTED
int PNGAPI
png_handle_as_unknown(png_structp png_ptr, png_bytep chunk_name)
{
   /* Check chunk_name and return "keep" value if it's on the list, else 0 */
   int i;
   png_bytep p;
   if (png_ptr == NULL || chunk_name == NULL || png_ptr->num_chunk_list<=0)
      return 0;
   p = png_ptr->chunk_list + png_ptr->num_chunk_list*5 - 5;
   for (i = png_ptr->num_chunk_list; i; i--, p -= 5)
      if (!png_memcmp(chunk_name, p, 4))
        return ((int)*(p + 4));
   return 0;
}
#endif

/* This function, added to libpng-1.0.6g, is untested. */
int PNGAPI
png_reset_zstream(png_structp png_ptr)
{
   if (png_ptr == NULL)
      return Z_STREAM_ERROR;
   return (inflateReset(&png_ptr->zstream));
}
#endif /* defined(PNG_READ_SUPPORTED) || defined(PNG_WRITE_SUPPORTED) */

/* This function was added to libpng-1.0.7 */
png_uint_32 PNGAPI
png_access_version_number(void)
{
   /* Version of *.c files used when building libpng */
   return((png_uint_32) PNG_LIBPNG_VER);
}


#if defined(PNG_READ_SUPPORTED) && defined(PNG_ASSEMBLER_CODE_SUPPORTED)
#ifndef PNG_1_0_X
/* This function was added to libpng 1.2.0 */
int PNGAPI
png_mmx_support(void)
{
   /* Obsolete, to be removed from libpng-1.4.0 */
    return -1;
}
#endif /* PNG_1_0_X */
#endif /* PNG_READ_SUPPORTED && PNG_ASSEMBLER_CODE_SUPPORTED */

#if defined(PNG_READ_SUPPORTED) || defined(PNG_WRITE_SUPPORTED)
#ifdef PNG_SIZE_T
/* Added at libpng version 1.2.6 */
   PNG_EXTERN png_size_t PNGAPI png_convert_size PNGARG((size_t size));
png_size_t PNGAPI
png_convert_size(size_t size)
{
   if (size > (png_size_t)-1)
      PNG_ABORT();  /* We haven't got access to png_ptr, so no png_error() */
   return ((png_size_t)size);
}
#endif /* PNG_SIZE_T */

/* Added at libpng version 1.2.34 and 1.4.0 (moved from pngset.c) */
#ifdef PNG_cHRM_SUPPORTED
#ifdef PNG_CHECK_cHRM_SUPPORTED

void /* PRIVATE */
png_64bit_product (long v1, long v2, unsigned long *hi_product,
   unsigned long *lo_product)
{
   int64_t x = (int64_t)v1 * (int64_t)v2;
   *hi_product = (unsigned long) (x >> 32);
   *lo_product = (unsigned long) x;
}

int /* PRIVATE */
png_check_cHRM_fixed(png_structp png_ptr,
   png_fixed_point white_x, png_fixed_point white_y, png_fixed_point red_x,
   png_fixed_point red_y, png_fixed_point green_x, png_fixed_point green_y,
   png_fixed_point blue_x, png_fixed_point blue_y)
{
   int ret = 1;
   unsigned long xy_hi,xy_lo,yx_hi,yx_lo;

   png_debug(1, "in function png_check_cHRM_fixed");

   if (png_ptr == NULL)
      return 0;

   if (white_x < 0 || white_y <= 0 ||
         red_x < 0 ||   red_y <  0 ||
       green_x < 0 || green_y <  0 ||
        blue_x < 0 ||  blue_y <  0)
   {
      png_warning(png_ptr,
        "Ignoring attempt to set negative chromaticity value");
      ret = 0;
   }
   if (white_x > (png_fixed_point) PNG_UINT_31_MAX ||
       white_y > (png_fixed_point) PNG_UINT_31_MAX ||
         red_x > (png_fixed_point) PNG_UINT_31_MAX ||
         red_y > (png_fixed_point) PNG_UINT_31_MAX ||
       green_x > (png_fixed_point) PNG_UINT_31_MAX ||
       green_y > (png_fixed_point) PNG_UINT_31_MAX ||
        blue_x > (png_fixed_point) PNG_UINT_31_MAX ||
        blue_y > (png_fixed_point) PNG_UINT_31_MAX )
   {
      png_warning(png_ptr,
        "Ignoring attempt to set chromaticity value exceeding 21474.83");
      ret = 0;
   }
   if (white_x > 100000L - white_y)
   {
      png_warning(png_ptr, "Invalid cHRM white point");
      ret = 0;
   }
   if (red_x > 100000L - red_y)
   {
      png_warning(png_ptr, "Invalid cHRM red point");
      ret = 0;
   }
   if (green_x > 100000L - green_y)
   {
      png_warning(png_ptr, "Invalid cHRM green point");
      ret = 0;
   }
   if (blue_x > 100000L - blue_y)
   {
      png_warning(png_ptr, "Invalid cHRM blue point");
      ret = 0;
   }

   png_64bit_product(green_x - red_x, blue_y - red_y, &xy_hi, &xy_lo);
   png_64bit_product(green_y - red_y, blue_x - red_x, &yx_hi, &yx_lo);

   if (xy_hi == yx_hi && xy_lo == yx_lo)
   {
      png_warning(png_ptr,
         "Ignoring attempt to set cHRM RGB triangle with zero area");
      ret = 0;
   }

   return ret;
}
#endif /* PNG_CHECK_cHRM_SUPPORTED */
#endif /* PNG_cHRM_SUPPORTED */

void /* PRIVATE */
png_check_IHDR(png_structp png_ptr,
   png_uint_32 width, png_uint_32 height, int bit_depth,
   int color_type, int interlace_type, int compression_type,
   int filter_type)
{
   int error = 0;

   /* Check for width and height valid values */
   if (width == 0)
   {
      png_warning(png_ptr, "Image width is zero in IHDR");
      error = 1;
   }

   if (height == 0)
   {
      png_warning(png_ptr, "Image height is zero in IHDR");
      error = 1;
   }

#ifdef PNG_SET_USER_LIMITS_SUPPORTED
   if (width > png_ptr->user_width_max || width > PNG_USER_WIDTH_MAX)
#else
   if (width > PNG_USER_WIDTH_MAX)
#endif
   {
      png_warning(png_ptr, "Image width exceeds user limit in IHDR");
      error = 1;
   }

#ifdef PNG_SET_USER_LIMITS_SUPPORTED
   if (height > png_ptr->user_height_max || height > PNG_USER_HEIGHT_MAX)
#else
   if (height > PNG_USER_HEIGHT_MAX)
#endif
   {
      png_warning(png_ptr, "Image height exceeds user limit in IHDR");
      error = 1;
   }

   if (width > PNG_UINT_31_MAX)
   {
      png_warning(png_ptr, "Invalid image width in IHDR");
      error = 1;
   }

   if ( height > PNG_UINT_31_MAX)
   {
      png_warning(png_ptr, "Invalid image height in IHDR");
      error = 1;
   }

   if ( width > (PNG_UINT_32_MAX
                 >> 3)      /* 8-byte RGBA pixels */
                 - 64       /* bigrowbuf hack */
                 - 1        /* filter byte */
                 - 7*8      /* rounding of width to multiple of 8 pixels */
                 - 8)       /* extra max_pixel_depth pad */
      png_warning(png_ptr, "Width is too large for libpng to process pixels");

   /* Check other values */
   if (bit_depth != 1 && bit_depth != 2 && bit_depth != 4 &&
       bit_depth != 8 && bit_depth != 16)
   {
      png_warning(png_ptr, "Invalid bit depth in IHDR");
      error = 1;
   }

   if (color_type < 0 || color_type == 1 ||
       color_type == 5 || color_type > 6)
   {
      png_warning(png_ptr, "Invalid color type in IHDR");
      error = 1;
   }

   if (((color_type == PNG_COLOR_TYPE_PALETTE) && bit_depth > 8) ||
       ((color_type == PNG_COLOR_TYPE_RGB ||
         color_type == PNG_COLOR_TYPE_GRAY_ALPHA ||
         color_type == PNG_COLOR_TYPE_RGB_ALPHA) && bit_depth < 8))
   {
      png_warning(png_ptr, "Invalid color type/bit depth combination in IHDR");
      error = 1;
   }

   if (interlace_type >= PNG_INTERLACE_LAST)
   {
      png_warning(png_ptr, "Unknown interlace method in IHDR");
      error = 1;
   }

   if (compression_type != PNG_COMPRESSION_TYPE_BASE)
   {
      png_warning(png_ptr, "Unknown compression method in IHDR");
      error = 1;
   }

#ifdef PNG_MNG_FEATURES_SUPPORTED
   /* Accept filter_method 64 (intrapixel differencing) only if
    * 1. Libpng was compiled with PNG_MNG_FEATURES_SUPPORTED and
    * 2. Libpng did not read a PNG signature (this filter_method is only
    *    used in PNG datastreams that are embedded in MNG datastreams) and
    * 3. The application called png_permit_mng_features with a mask that
    *    included PNG_FLAG_MNG_FILTER_64 and
    * 4. The filter_method is 64 and
    * 5. The color_type is RGB or RGBA
    */
   if ((png_ptr->mode & PNG_HAVE_PNG_SIGNATURE) &&
       png_ptr->mng_features_permitted)
      png_warning(png_ptr, "MNG features are not allowed in a PNG datastream");

   if (filter_type != PNG_FILTER_TYPE_BASE)
   {
      if (!((png_ptr->mng_features_permitted & PNG_FLAG_MNG_FILTER_64) &&
         (filter_type == PNG_INTRAPIXEL_DIFFERENCING) &&
         ((png_ptr->mode & PNG_HAVE_PNG_SIGNATURE) == 0) &&
         (color_type == PNG_COLOR_TYPE_RGB ||
         color_type == PNG_COLOR_TYPE_RGB_ALPHA)))
      {
         png_warning(png_ptr, "Unknown filter method in IHDR");
         error = 1;
      }

      if (png_ptr->mode & PNG_HAVE_PNG_SIGNATURE)
      {
         png_warning(png_ptr, "Invalid filter method in IHDR");
         error = 1;
      }
   }

#else
   if (filter_type != PNG_FILTER_TYPE_BASE)
   {
      png_warning(png_ptr, "Unknown filter method in IHDR");
      error = 1;
   }
#endif

   if (error == 1)
      png_error(png_ptr, "Invalid IHDR data");
}
#endif /* defined(PNG_READ_SUPPORTED) || defined(PNG_WRITE_SUPPORTED) */
