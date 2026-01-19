
#include "bajo.h"
#include "dsmr.h"

namespace esphome {
namespace dsmr_custom {

// Logging tag for the main component
static const char *const TAG = "BAJO dsmr_custom";

void Bajo::BAJO_setup(){
    Dsmr *d = static_cast<Dsmr*>(this); // access to Dsmr fields (must be Dsmr object)
    ESP_LOGI(TAG, "Initializing BAJO support...");
    ESP_LOGI(TAG, "Method: %d", static_cast<int>(this->method_));

    this->decrypted_body_ = new char[d->max_telegram_len_ + 1];
    if (this->decrypted_body_ == nullptr) {
        ESP_LOGE(TAG, "Failed to allocate decrypted_body_ buffer!");
        d->mark_failed();
    }
    this->header_ = new char[20 + 1];
    if (this->header_ == nullptr) {
        ESP_LOGE(TAG, "Failed to allocate header_ buffer!");
        d->mark_failed();
    }
    this->body_ = new uint8_t[d->max_telegram_len_ + 1];
    if (this->body_ == nullptr) {
        ESP_LOGE(TAG, "Failed to allocate body_ buffer!");
        d->mark_failed();
    }
    this->footer_ = new char[20 + 1];
    if (this->footer_ == nullptr) {
        ESP_LOGE(TAG, "Failed to allocate footer_ buffer!");
        d->mark_failed();
    }
    this->rx_buffer_ = new uint8_t[2000];
    if (this->rx_buffer_ == nullptr) {
        ESP_LOGE(TAG, "Failed to allocate rx_buffer_ buffer!");
        d->mark_failed();
    }

    // IP configuration for UDP socket
    this->hints.ai_family = AF_INET; // IPv4
    this->hints.ai_socktype = SOCK_DGRAM; // UDP
    this->hints.ai_flags = AI_PASSIVE; // Użyj adresu lokalnego
    int err = getaddrinfo("192.168.22.233", "37008", &hints, &address_info);
    if (err != 0 || address_info == NULL) {
        ESP_LOGE(TAG, "getaddrinfo failed: %d", err);
    }
	
	memset(&this->udp_recv, 0, sizeof(this->udp_recv));
	this->udp_recv.sin_family = AF_INET;
	this->udp_recv.sin_port = 37008;
	inet_pton(AF_INET, "192.168.22.27", &this->udp_recv.sin_addr);
    //net_pton(AF_INET, "192.168.22.238", &this->udp_recv.sin_addr);

    //socket creation
    this->sock = socket(address_info->ai_family, address_info->ai_socktype, address_info->ai_protocol);
    if (this->sock < 0) {
        ESP_LOGE(TAG, "Unable to create socket: errno %d", errno);
        freeaddrinfo(address_info);
        vTaskDelete(NULL);
    } else {
		ESP_LOGI(TAG, "Socket created");
	}
    
	if (this->tx_buffer == NULL) {
        this->tx_buffer = (char*)malloc(1500);
        if (this->tx_buffer == NULL) {
            ESP_LOGE(TAG, "Failed to allocate memory for tx_buffer");
            free(this->tx_buffer); // Zwolnij wcześniej zaalokowaną pamięć
        }else{
			this->tx_buffer[0] = 0;
			ESP_LOGI(TAG, "Allocated memory for tx_buffer size %d", 1500);
		}
	}


}

void Bajo::BAJO_reset_telegram(){
    Dsmr *d = static_cast<Dsmr*>(this); // access to Dsmr fields (must be Dsmr object)    
    this->start_milis_ = 0;
    this->precessed_bytes_ = 0;
    this->header_found_ = false;
    this->header_completed_ = false;
    this->header_[0] = 0;
    this->empty_line_completed_ = false;
    this->footer_found_ = false;
    this->footer_completed_ = false;
    this->footer_[0] = 0;
    this->body_[0] = 0;
    this->body_bytes_ = 0;
    this->bodyPos_ = 0;
    this->bytes_read_ = 0;
    this->crcPos_ = 0;
    if (d->telegram_ != nullptr) {
        for (size_t i = 0; i < d->max_telegram_len_; i++) {
        d->telegram_[i] = 0;
        }
    }
    if (this->decrypted_body_ != nullptr) {
        this->decrypted_body_[0] = '\0';
    }
    this->decrypted_body_bytes_ = 0;
  
    d->crypt_bytes_read_ = 0;
    d->crypt_telegram_len_ = 0;

}
void Bajo::BAJO_send_udp_telegram(char *tx_buffer, int len) {
  //Function to send UDP telegram to PC for debugging purposes
    Dsmr *d = static_cast<Dsmr*>(this); // access to Dsmr fields (must be Dsmr object)
	int err = sendto(this->sock, tx_buffer, len, 0, (struct sockaddr *)&this->udp_recv, sizeof(this->udp_recv));
    if (err < 0) {
        ESP_LOGE(TAG, "Error occurred during sending: errno %d", errno);
    }
}

void Bajo::BAJO_receive_telegram() {
    Dsmr *d = static_cast<Dsmr*>(this); // access to Dsmr fields (must be Dsmr object)  
    int len = d->available();

    if (len != 0) {
        // Read available bytes into rx_buffer_
        // Taking all available bytes at once
        // It is faster than reading one by one and checking for end of data
        //ESP_LOGI(TAG, "Reading %d bytes from UART", len);
        bool r = d->read_array(d->rx_buffer_ + d->rx_buffer_len_, len);
        d->rx_buffer_len_ += len;
   	    d->last_receive_time_ = millis();
    }
    
//    ESP_LOGI(TAG, "last_receive_time %d, %d", d->last_receive_time_, millis() - d->last_receive_time_);

    if ((d->last_receive_time_ != 0)  && (millis() - d->last_receive_time_ > 200)) {
        //  200ms after last byte, process telegram

        //BAJO_send_udp_telegram_((char*)d->rx_buffer_, d->rx_buffer_len_);        
        //ESP_LOGI(TAG, "Got telegram %d bytes", d->rx_buffer_len_);
      
        d->reset_telegram_();
        this->BAJO_process_telegram();
        d->last_receive_time_ = 0;
        d->rx_buffer_len_ = 0; 
    }

    return;
}

void Bajo::BAJO_process_telegram() {
    Dsmr *d = static_cast<Dsmr*>(this); // access to Dsmr fields (must be Dsmr object)
    int x = 0;
    char c;

    //ESP_LOGI(TAG, "Start processing telegram from rx_buffer_ size %d", d->rx_buffer_len_);  
    while (x <= d->rx_buffer_len_){

        c = d->rx_buffer_[x];
    
        if (x % 25 == 0){
	        //ESP_LOGI(TAG, "Processed %d, %02X '%c', bytes %d, Time  %ums, hdr %d, hdr_cmp %d, empty_cmp %d, foot %d, foot_cmp %d", x, c, isprint(c) ? c : '.', d->bytes_read_, millis() - d->start_milis_, d->header_found_, d->header_completed_, d->empty_line_completed_, d->footer_found_, d->footer_completed_);   
        }
        if (d->bytes_read_ >= d->max_telegram_len_) {
            ESP_LOGE(TAG, "Error: Plain telegram larger than buffer (%zu bytes). Discarding.", d->max_telegram_len_);
            d->reset_telegram_();
            d->stop_requesting_data_();
            return;
        }
	    if (!d->header_found_) {  
            if (c == '/') {
                //ESP_LOGI(TAG, "Header of plain telegram found ('/').");
                d->reset_telegram_();
                d->header_found_ = true;
                d->last_read_time_ = millis();
                d->start_milis_ = millis();

            }else{
                x++;
                continue;
            }
        }
	    if ((d->header_found_) && (!d->header_completed_)) {
		    if (c == '\r') {
                char e = d->rx_buffer_[x+1];

			    if (e == '\n') {
			        d->header_completed_ = true;
                    //ESP_LOGI(TAG, "Header completed.");
				    d->telegram_[d->bytes_read_] = 0;
				    strcpy (d->header_, d->telegram_);
			    }
			    d->telegram_[d->bytes_read_] = c;
			    d->bytes_read_++;
			    d->telegram_[d->bytes_read_] = e;
			    d->bytes_read_++;
                x++;
                x++;
		    }else{
                d->telegram_[d->bytes_read_] = c;
		        d->bytes_read_++;
                x++;
		    }
		    continue;
	    }
	    if ((d->header_completed_) && (!d->empty_line_completed_)){
		    if (c == '\r') {
                char e = d->rx_buffer_[x+1];
			    d->telegram_[d->bytes_read_] = c;
			    d->bytes_read_++;
			    d->telegram_[d->bytes_read_] = e;
			    d->bytes_read_++;
                x++;
                x++;
			    if (e == '\n') {
    				d->empty_line_completed_ = true;
                    //ESP_LOGI(TAG, "Empty line after header completed.");
		    		d->bodyPos_ = d->bytes_read_;
			    }
		    }else{
                d->telegram_[d->bytes_read_] = c;
		        d->bytes_read_++;
                x++;
		    }
		    continue;
	    }

        if ((d->empty_line_completed_) && (!d->footer_found_)) {
            if  (c == '!') {
                // Potencial footer start detected
                // Potencial, because '!' can appear in body as well
                // Looking for '!' xx xx xx CR LF
                //ESP_LOGI(TAG, "Potential footer start detected ('!').");
	            d->footer_[0] = d->rx_buffer_[x+1];
		        d->footer_[1] = d->rx_buffer_[x+2];
                d->footer_[2] = d->rx_buffer_[x+3];
		        d->footer_[3] = d->rx_buffer_[x+4];
		        d->footer_[4] = 0;
                char e = d->rx_buffer_[x+5];  
		        if (e == '\r') {
                    //ESP_LOGI(TAG, "Footer 1st char '!' followed by CR found.");
                    char f = d->rx_buffer_ [x+6];
			        d->telegram_[d->bytes_read_] = '!';
			        d->bytes_read_++;
                    x++;

                    if (f == '\n') {
                        //Footer really founded

                        d->footer_found_ = true;
				        d->footer_completed_ = true;

				        d->crcPos_ = d->bytes_read_;
                        //ESP_LOGI(TAG, "Footer found ('!').");

			        }else{
                        //ESP_LOGI(TAG, "False footer alarm. Continuing body processing.");
                        d->body_[d->body_bytes_] = '!';
	    			    d->body_bytes_++;
		    		    d->body_[d->body_bytes_] = d->footer_[0];
			    	    d->body_bytes_++;
				        d->body_[d->body_bytes_] = d->footer_[1];
				        d->body_bytes_++;
				        d->body_[d->body_bytes_] = d->footer_[2];
				        d->body_bytes_++;
				        d->body_[d->body_bytes_] = d->footer_[3];
				        d->body_bytes_++;
				        d->body_[d->body_bytes_] = e;
				        d->body_bytes_++;
				        d->body_[d->body_bytes_] = f;
				        d->body_bytes_++;
                    }
                    //ESP_LOGI(TAG, "Footer completed.");
			        d->telegram_[d->bytes_read_] = d->footer_[0];
			        d->bytes_read_++;
			        d->telegram_[d->bytes_read_] = d->footer_[1];
			        d->bytes_read_++;
			        d->telegram_[d->bytes_read_] = d->footer_[2];
			        d->bytes_read_++;
			        d->telegram_[d->bytes_read_] = d->footer_[3];
			        d->bytes_read_++;
			        d->telegram_[d->bytes_read_] = e;
			        d->bytes_read_++;
			        d->telegram_[d->bytes_read_] = f;
			        d->bytes_read_++;
                    x+=6;

                }else{
                    //ESP_LOGI(TAG, "False footer alarm. Continuing body processing.");
                    d->body_[d->body_bytes_] = '!';
			        d->body_bytes_++;
			        d->telegram_[d->bytes_read_] = '!';
			        d->bytes_read_++;
			        d->body_[d->body_bytes_] = d->footer_[0];
			        d->body_bytes_++;
			        d->telegram_[d->bytes_read_] = d->footer_[0];
			        d->bytes_read_++;
			        d->body_[d->body_bytes_] = d->footer_[1];
			        d->body_bytes_++;
			        d->telegram_[d->bytes_read_] = d->footer_[1];
			        d->bytes_read_++;
			        d->body_[d->body_bytes_] = d->footer_[2];
			        d->body_bytes_++;
			        d->telegram_[d->bytes_read_] = d->footer_[2];
			        d->bytes_read_++;
			        d->body_[d->body_bytes_] = d->footer_[3];
			        d->body_bytes_++;
			        d->telegram_[d->bytes_read_] = d->footer_[3];
			        d->bytes_read_++;
			        d->body_[d->body_bytes_] = e;
			        d->body_bytes_++;
			        d->telegram_[d->bytes_read_] = e;
			        d->bytes_read_++;
			
                    x+=5;

			        d->footer_[0] = 0;
		        }
	        }else{
                //ESP_LOGI(TAG, "Body byte added: %02X '%c'", c, isprint(c) ? c : '.');
		        d->telegram_[d->bytes_read_] = c;
		        d->bytes_read_++;
                x++;
		
		        d->body_[d->body_bytes_] = c;
		        d->body_bytes_++;
                continue;
	        }
        }
        //ESP_LOGI(TAG, "RX_BUFF %02X c %02X", d->rx_buffer_[x], c);
	    //BAJO_send_udp_telegram_(d->telegram_, d->bytes_read_);   //For debuging I sent telegram to my host PC

        if (d->footer_completed_){
            //Footer completed, means we have full telegram
            //Try to decrypt it
            d->body_[d->body_bytes_] = '\0';
	        d->telegram_[d->bytes_read_] = '\0';
            //ESP_LOGI(TAG, "Processed %d, %02X '%c', bytes %d, Time  %ums, hdr %d, hdr_cmp %d, empty_cmp %d, foot %d, foot_cmp %d", x, c, isprint(c) ? c : '.', d->bytes_read_, millis() - d->start_milis_, d->header_found_, d->header_completed_, d->empty_line_completed_, d->footer_found_, d->footer_completed_);   
	        //ESP_LOGI(TAG, "Telegram total bytes %d, Time  %ums", d->bytes_read_, millis() - d->start_milis_);

    	    //BAJO_send_udp_telegram(d->telegram_, d->bytes_read_);   //For debuging I sent telegram to my host PC

            this->BAJO_decrypt_telegram();

            memcpy(d->telegram_+d->bodyPos_, d->decrypted_body_, d->decrypted_body_bytes_);
            memcpy(d->telegram_+d->bodyPos_ + d->decrypted_body_bytes_ + 1, d->footer_, strlen(d->footer_) + 1);
    
            d->telegram_[d->bodyPos_ + d->decrypted_body_bytes_ ] = '!';
            d->crcPos_ = d->bodyPos_ + d->decrypted_body_bytes_;
    
            d->bytes_read_ = d->bodyPos_ + d->decrypted_body_bytes_ + 1 + strlen(d->footer_);
            d->telegram_[d->bytes_read_] = 13;
            d->telegram_[d->bytes_read_+1] = 10;
            d->telegram_[d->bytes_read_+2] = '\0';
            d->bytes_read_ +=2;

            //BAJO_send_udp_telegram(d->telegram_, d->bytes_read_);   //For debuging I sent telegram to my host PC
    

            //ESP_LOGI(TAG, "Telegram ->%s<- bytes %d", d->telegram_, d->bytes_read_);	
	        //ESP_LOGI(TAG, "");
	        //ESP_LOGI(TAG, "Header ->%s<- bytes %d", d->header_, strlen(d->header_));	
	        //ESP_LOGI(TAG, "Body ->%02X %02X %02X %02X .. %02X %02X %02X %02X<- bytes %d", d->body_[0], d->body_[1], d->body_[2], d->body_[3], d->body_[d->body_bytes_-4], d->body_[d->body_bytes_-3] , d->body_[d->body_bytes_-2], d->body_[d->body_bytes_-1], d->body_bytes_);	
	        //ESP_LOGI(TAG, "Footer (CRC) ->%02X %02X %02X %02X<- ->%s<- bytes %d", d->footer_[0], d->footer_[1], d->footer_[2], d->footer_[3], d->footer_, strlen(d->footer_));	
	        //ESP_LOGI(TAG, "Header ->%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X<-", d->header_[0], d->header_[1], d->header_[2], d->header_[3], d->header_[4], d->header_[5], d->header_[6], d->header_[6], d->header_[7], d->header_[8], d->header_[9], d->header_[10]);
            //ESP_LOGI(TAG, "crc    ->%02X %02X %02X %02X<- crcPos %d", d->telegram_[d->crcPos_ - 2], d->telegram_[d->crcPos_-1], d->telegram_[d->crcPos_], d->telegram_[d->crcPos_+1], d->crcPos_);	
            //ESP_LOGI(TAG, "0x0000 ->%02X %02X %02X %02X %02X %02X %02X %02X<-  %d", d->telegram_[0], d->telegram_[1], d->telegram_[2], d->telegram_[3], d->telegram_[4], d->telegram_[5], d->telegram_[6], d->telegram_[7], d->bytes_read_);		  
            //ESP_LOGI(TAG, "0x0008 ->%02X %02X %02X %02X %02X %02X %02X %02X<-  %d", d->telegram_[8], d->telegram_[9], d->telegram_[10], d->telegram_[11], d->telegram_[12], d->telegram_[13], d->telegram_[14], d->telegram_[15], d->bytes_read_);		  	  
            //ESP_LOGI(TAG, "body   ->%02X %02X %02X %02X %02X %02X %02X %02X<-  %d", d->telegram_[d->bodyPos_], d->telegram_[d->bodyPos_+1], d->telegram_[d->bodyPos_+2], d->telegram_[d->bodyPos_+3], d->telegram_[d->bodyPos_+4], d->telegram_[d->bodyPos_+5], d->telegram_[d->bodyPos_+6], d->telegram_[d->bodyPos_+7], d->bodyPos_);		  
            //ESP_LOGI(TAG, "       ->%02X %02X %02X %02X %02X %02X %02X %02X %02X<-  %d", d->telegram_[d->bytes_read_-7], d->telegram_[d->bytes_read_-6], d->telegram_[d->bytes_read_-5], d->telegram_[d->bytes_read_-4], d->telegram_[d->bytes_read_-3], d->telegram_[d->bytes_read_-2], d->telegram_[d->bytes_read_-1], d->telegram_[d->bytes_read_], d->telegram_[d->bytes_read_+1], d->bytes_read_);	
	        ESP_LOGI(TAG, "Telegram total bytes %d, Process time  %ums", d->bytes_read_, millis() - d->start_milis_);

            d->parse_telegram();
            d->reset_telegram_();
            return;

        }   
  
    x++;
    }

}


void Bajo::BAJO_decrypt_telegram(){
	Dsmr *d = static_cast<Dsmr*>(this); // dostęp do pól Dsmr (musi być obiekt Dsmr)
    size_t system_title_length = 0;

    if (d->body_[0] == 0x00) {
		// 00 means empty system title
		system_title_length	= 1;
	}else if (d->body_[0] == 0xDB) {
		// DB means we have system title
    // next byte is length of system title
		system_title_length = d->body_[1] + 2;
	}else{
    // other system not known
		ESP_LOGE(TAG, "Decryptor, StartByte not found");
        return;
    }

    size_t ciphertext_offset = system_title_length + 8;
    size_t gcm_tag_length = 0;
    size_t len_info_from_frame = (static_cast<size_t>(d->body_[system_title_length + 1]) << 8) | static_cast<size_t>(d->body_[system_title_length + 2]);

    //ESP_LOGI(TAG, "->%02X %02X<- len_info_from frame %d", this->body_[system_title_length + 1], this->body_[system_title_length + 2], len_info_from_frame);

    if (d->body_bytes_ < (ciphertext_offset + gcm_tag_length) || len_info_from_frame == 0) {
        ESP_LOGE(TAG, "Encrypted data too short for IV, ciphertext, and GCM tag, or LEN_INFO is zero. Read: %zu, LEN_INFO: %zu", d->body_bytes_, len_info_from_frame);
        //this->reset_telegram_(); this->stop_requesting_data_(); return;
    }

    
    size_t ciphertext_len = len_info_from_frame - gcm_tag_length - 5;

	if (ciphertext_offset + ciphertext_len + gcm_tag_length != d->body_bytes_) {
    ESP_LOGE(TAG, "Encrypted frame length mismatch. Expected based on LEN_INFO: %zu, Actual bytes read: %zu", ciphertext_offset + ciphertext_len + gcm_tag_length, d->body_bytes_);
		ESP_LOGE(TAG, "Length from frame read: %d, Ciphertext offset: %d, Ciphertext length: %d,  gcm_tag_length: %d", len_info_from_frame, ciphertext_offset, ciphertext_len, gcm_tag_length);
    //d->reset_telegram_(); d->stop_requesting_data_(); 
    //return;
    }
    
    uint8_t iv[12] = {0};
    if (system_title_length > 8){
      memcpy(iv, &d->body_[2], 8);
    }
    memcpy(iv + 8, &d->body_[system_title_length + 4], 4);

    uint8_t* ciphertext_ptr = &d->body_[ciphertext_offset];
    uint8_t* tag_ptr = &d->body_[ciphertext_offset + ciphertext_len];
    
	if (ciphertext_len > d->max_telegram_len_) {
    ESP_LOGE(TAG, "Decrypted data length (%zu) would exceed plain telegram_ buffer (%zu).", ciphertext_len, d->max_telegram_len_);
    //d->reset_telegram_(); d->stop_requesting_data_();
    //eturn;
    }
    
    ciphertext_len -= 12; // adjusting length to exclude GCM tag for decryption

#ifdef USE_ARDUINO
    // Arduino: Use Crypto library
    GCM<AES128> gcmaes128;

    gcmaes128.setKey(d->decryption_key_.data(), gcmaes128.keySize());

    
    gcmaes128.setIV(iv, sizeof(iv));
    //ESP_LOGI(TAG, "Decryption IV (Hex): %02X %02X %02X %02X %02X %02X %02X %02X    %02X %02X %02X %02X",
    //             iv[0], iv[1], iv[2], iv[3], iv[4], iv[5], iv[6], iv[7], iv[8], iv[9], iv[10], iv[11]);
    

	gcmaes128.decrypt(reinterpret_cast<uint8_t *>(d->decrypted_body_), ciphertext_ptr, ciphertext_len);
    if (!gcmaes128.checkTag(tag_ptr, gcm_tag_length)) {
        ESP_LOGW(TAG, "Decryption failed! GCM tag mismatch.");
        ESP_LOGW(TAG, "GCM tag: %02X %02X %02X %02X .. %02X %02X %02X %02X", 
                 tag_ptr[0], tag_ptr[1], tag_ptr[2], tag_ptr[3],
                 tag_ptr[gcm_tag_length - 4], tag_ptr[gcm_tag_length - 3],
                 tag_ptr[gcm_tag_length - 2], tag_ptr[gcm_tag_length - 1]);
        //d->reset_telegram_(); d->stop_requesting_data_(); 
        //return;
    }
#else

    // ESP-IDF: Use vendored MbedTLS wrapper
    int decrypt_result = dsmr_aes_gcm_decrypt(
        d->decryption_key_.data(),
        d->decryption_key_.size(),
        iv,
        sizeof(iv),
        ciphertext_ptr,
        ciphertext_len,
        tag_ptr,
        gcm_tag_length,
        reinterpret_cast<uint8_t *>(d->decrypted_body_));

    //BAJO_send_udp_telegram(d->decrypted_body_, ciphertext_len);   //For debuging I sent telegram to my host PC            

    if (decrypt_result != 0) {
      ESP_LOGW(TAG, "Decryption failed! Error code: %d", decrypt_result);
      //d->reset_telegram_();
      //d->stop_requesting_data_();
      //return;
    }
    //ESP_LOGD(TAG, "ESP-IDF: Decryption successful using vendored MbedTLS.");
#endif



    d->decrypted_body_[ciphertext_len] = '\0';
    d->decrypted_body_bytes_ = ciphertext_len;
    //ESP_LOGD(TAG, "Decryption successful. Decrypted body bytes: %zu bytes.", this->decrypted_body_bytes_);
    //ESP_LOGI(TAG, "Decrypted P1 telegram content:->\n%s\n<- ", this->decrypted_body_);

}




}  // namespace dsmr_custom
}  // namespace esphome