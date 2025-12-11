idf_component_register(SRCS "bajo.cpp" "dsmr.cpp"
                             "dsmr_crypto_impl.cpp"
                             "fields.cpp"
                       INCLUDE_DIRS "."
                       REQUIRES mbedtls)
