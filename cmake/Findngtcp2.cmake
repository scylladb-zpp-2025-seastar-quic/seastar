set (NGTCP2_ENABLE_LIB_ONLY    
  ON  
  CACHE 
  BOOL 
  "Build libngtcp2 only")

set (NGTCP2_ENABLE_STATIC_LIB  
  ON  
  CACHE 
  BOOL 
  "Build static lib")

set (NGTCP2_ENABLE_SHARED_LIB  
  OFF 
  CACHE 
  BOOL 
  "Disable shared lib")

set (NGTCP2_ENABLE_GNUTLS      
  ON  
  CACHE 
  BOOL 
  "Enable GnuTLS")

set (NGTCP2_ENABLE_OPENSSL     
  OFF 
  CACHE 
  BOOL 
  "Disable OpenSSL")

set (NGTCP2_DISABLE_TESTS      
  ON
  CACHE
  BOOL 
  "Disable tests")

enable_language (C)

# cmake-cooking wraps project() and skips nested invocations in subdirectories.
# Seed ngtcp2's project version variables so its CMakeLists can still derive
# PACKAGE_VERSION_NUM when built through Seastar's DPDK workflow.
if (DEFINED PROJECT_VERSION)
  set (_ngtcp2_saved_project_version "${PROJECT_VERSION}")
  set (_ngtcp2_saved_project_version_defined ON)
else ()
  set (_ngtcp2_saved_project_version_defined OFF)
endif ()

if (DEFINED PROJECT_VERSION_MAJOR)
  set (_ngtcp2_saved_project_version_major "${PROJECT_VERSION_MAJOR}")
  set (_ngtcp2_saved_project_version_major_defined ON)
else ()
  set (_ngtcp2_saved_project_version_major_defined OFF)
endif ()

if (DEFINED PROJECT_VERSION_MINOR)
  set (_ngtcp2_saved_project_version_minor "${PROJECT_VERSION_MINOR}")
  set (_ngtcp2_saved_project_version_minor_defined ON)
else ()
  set (_ngtcp2_saved_project_version_minor_defined OFF)
endif ()

if (DEFINED PROJECT_VERSION_PATCH)
  set (_ngtcp2_saved_project_version_patch "${PROJECT_VERSION_PATCH}")
  set (_ngtcp2_saved_project_version_patch_defined ON)
else ()
  set (_ngtcp2_saved_project_version_patch_defined OFF)
endif ()

set (PROJECT_VERSION "1.21.90")
set (PROJECT_VERSION_MAJOR 1)
set (PROJECT_VERSION_MINOR 21)
set (PROJECT_VERSION_PATCH 90)

add_subdirectory (ngtcp2)

if (_ngtcp2_saved_project_version_defined)
  set (PROJECT_VERSION "${_ngtcp2_saved_project_version}")
else ()
  unset (PROJECT_VERSION)
endif ()

if (_ngtcp2_saved_project_version_major_defined)
  set (PROJECT_VERSION_MAJOR "${_ngtcp2_saved_project_version_major}")
else ()
  unset (PROJECT_VERSION_MAJOR)
endif ()

if (_ngtcp2_saved_project_version_minor_defined)
  set (PROJECT_VERSION_MINOR "${_ngtcp2_saved_project_version_minor}")
else ()
  unset (PROJECT_VERSION_MINOR)
endif ()

if (_ngtcp2_saved_project_version_patch_defined)
  set (PROJECT_VERSION_PATCH "${_ngtcp2_saved_project_version_patch}")
else ()
  unset (PROJECT_VERSION_PATCH)
endif ()

set (NGTCP2_SRC "${CMAKE_CURRENT_SOURCE_DIR}/ngtcp2")
set (NGTCP2_BIN "${CMAKE_CURRENT_BINARY_DIR}/ngtcp2")

set (ngtcp2_INCLUDE_DIRS
  "${NGTCP2_SRC}/lib/includes"     
  "${NGTCP2_SRC}/crypto/includes"  
  "${NGTCP2_SRC}/lib"              
  "${NGTCP2_BIN}/lib/includes"     
)

if (TARGET ngtcp2_static AND TARGET ngtcp2_crypto_gnutls_static)
  add_library (ngtcp2::ngtcp2 INTERFACE IMPORTED)

  set_target_properties(ngtcp2_static PROPERTIES 
    POSITION_INDEPENDENT_CODE ON
  )
  
  set_target_properties(ngtcp2_crypto_gnutls_static PROPERTIES
    POSITION_INDEPENDENT_CODE ON
  )

  set_target_properties (ngtcp2::ngtcp2 PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${ngtcp2_INCLUDE_DIRS}"
  )

  target_link_libraries(ngtcp2::ngtcp2
    INTERFACE
      ngtcp2_static
      ngtcp2_crypto_gnutls_static
  )

  set (ngtcp2_FOUND TRUE)
else()
  message (FATAL_ERROR "[ngtcp2] CRITICAL: targets of ngtcp2 library haven't been found!")
endif()

include (FindPackageHandleStandardArgs)

find_package_handle_standard_args (ngtcp2 
  REQUIRED_VARS 
    ngtcp2_FOUND)
