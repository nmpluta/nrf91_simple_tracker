#ifndef MQTT_CONNECTION_H
#define MQTT_CONNECTION_H

#define LED_CONTROL_OVER_MQTT          DK_LED2 /*The LED to control over MQTT*/
#define IMEI_LEN 15
#define CGSN_RESPONSE_LENGTH (IMEI_LEN + 6 + 1) /* Add 6 for \r\nOK\r\n and 1 for \0 */
#define CLIENT_ID_LEN sizeof("nrf-") + IMEI_LEN

int client_init(struct mqtt_client * p_client);
int fds_init(struct mqtt_client * p_client, struct pollfd * p_fds);
int data_publish(struct mqtt_client * p_client, enum mqtt_qos qos, uint8_t * data, size_t len);

#endif /* MQTT_CONNECTION_H */
