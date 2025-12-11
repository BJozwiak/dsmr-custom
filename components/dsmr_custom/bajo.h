#pragma once

#ifndef BAJO_H // Unique include guard for your hub component
#define BAJO_H

    #include "esphome/core/component.h"
    #include "esphome/components/sensor/sensor.h"
    #include "esphome/components/text_sensor/text_sensor.h"
    #include "esphome/components/uart/uart.h"
    #include "esphome/core/hal.h"      // For hardware abstraction layer utilities (e.g., GPIOPin).
    #include "esphome/core/log.h"      // For ESP_LOGx logging macros.
    #include "esphome/core/defines.h"  // For common ESPHome defines.
    #include "esphome/core/optional.h" // For esphome::optional
    
    #include "parser.h"
    #include "fields.h"
    #include "util.h"
    #include "crc16.h"

    #include <map>

    // Cryptography libraries for AES-GCM decryption
    #ifdef USE_ARDUINO
        #include <AES.h>
        #include <GCM.h>
    #else
        // ESP-IDF: Use vendored MbedTLS wrapper
        #include "dsmr_crypto.h"
    #endif


    #include <sys/socket.h>
	#include <netdb.h>
    #define INVALID_SOCK (-1)

    enum Methods {
        plain,
        crypted,
        poland_stoen = 5,
        BAJO = 5
    };

    namespace esphome {
    namespace dsmr_custom {

        //Forward declaration of Dsmr class
        class Dsmr;

        class Bajo {
            public:
                virtual ~Bajo() = default;

                void set_method(const std::string &value) { std::map<std::string, Methods> methods = {{"plain", plain}, {"crypted", crypted}, {"poland_stoen", poland_stoen}, {"bajo", BAJO}}; auto it = methods.find(value); if (it != methods.end())  { method_ = it->second; } }

                void BAJO_setup();
                void BAJO_reset_telegram();
	            void BAJO_decrypt_telegram();
                void BAJO_receive_telegram();
                void BAJO_process_telegram();
                void BAJO_send_udp_telegram(char *tx_buffer, int len);
                
            protected:
                Methods method_{Methods::plain};

                uint32_t last_receive_time_{0};
                size_t bytes_read_{0};
                uint32_t start_milis_{0};
            	size_t precessed_bytes_{0};
                bool header_found_{false};
	            bool header_completed_{false};
	            bool empty_line_completed_{false};
	            char *header_{nullptr};
                uint8_t *body_{nullptr};
                size_t body_bytes_{0};
	            uint16_t bodyPos_{0};
	            char *decrypted_body_{nullptr};
                size_t decrypted_body_bytes_{0};
          	    bool footer_found_{false};
	            bool footer_completed_{false};
	            char *footer_{nullptr};
                uint16_t crcPos_{0};
                uint8_t *rx_buffer_{nullptr};
                size_t rx_buffer_len_{0};
	            char *tx_buffer{nullptr};

                
                struct addrinfo hints{0};
        	    struct addrinfo *address_info{};
                int sock{INVALID_SOCK};
	            struct sockaddr_in udp_recv{};


        };
    }  // namespace dsmr_custom
    }  // namespace esphome

#endif // BAJO_H