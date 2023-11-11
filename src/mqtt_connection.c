#include <stdio.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/random/rand32.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/mqtt.h>
#include <nrf_modem_at.h>
#include <zephyr/logging/log.h>
#include <dk_buttons_and_leds.h>
#include <modem/modem_key_mgmt.h>

#include "mqtt_connection.h"
#include "certificate.h"

LOG_MODULE_DECLARE(nrf91_simple_tracker, LOG_LEVEL_INF);

/* Buffers for MQTT client. */
static uint8_t rx_buffer[CONFIG_MQTT_MESSAGE_BUFFER_SIZE];
static uint8_t tx_buffer[CONFIG_MQTT_MESSAGE_BUFFER_SIZE];
static uint8_t payload_buf[CONFIG_MQTT_PAYLOAD_BUFFER_SIZE];

/* MQTT Broker details. */
static struct sockaddr_storage broker;

/**@brief Function to subscribe to the configured topic
 *
 * @param[in] p_client Pointer to MQTT client structure
 */
int subscribe(struct mqtt_client * p_client)
{
    int err;

    /* Define MQTT subscribe topic */
    struct mqtt_topic sub_topic = {
        .topic = {
            .utf8 = CONFIG_MQTT_SUB_TOPIC,
            .size = strlen(CONFIG_MQTT_SUB_TOPIC)
        },
        .qos = MQTT_QOS_1_AT_LEAST_ONCE,
    };

    /* Define MQTTT subscription list */
    const struct mqtt_subscription_list subscription_list = {
        .list = &sub_topic,
        .list_count = 1,
        .message_id = sys_rand32_get()
    };

    /* Subscribe to MQTT topic */
    err = mqtt_subscribe(p_client, &subscription_list);
    if (err < 0)
    {
        LOG_ERR("Failed to subscribe to topic, error: %d", err);
    }
    else
    {
        LOG_INF("Subscribed to topic: %s", CONFIG_MQTT_SUB_TOPIC);
    }

    return err;
}

/**@brief Function to get the payload of recived data.
 *
 * @param[in] p_client Pointer to MQTT client structure
 *
 * @return 0 or a negative error code (errno.h) indicating reason of failure.
 *
 * @note - 0 indicates that the payload was successfully read.
 *       - -EMSGSIZE indicates that the payload was too large to fit in the
 *       payload buffer.
 *       - -EIO indicates that the payload could not be read (I/O error).
 *       - other negative errno.h error codes can be returned by the
 *       mqtt_read_publish_payload_blocking() and mqtt_readall_publish_payload().
 */
static int get_received_payload(struct mqtt_client * p_client, size_t length)
{
    int ret;
    int err = 0;

    /* Clear the payload buffer. */
    memset(payload_buf, 0x0, sizeof(payload_buf));

    /* Return an error if the payload is larger than the payload buffer.
     * Note: To allow new messages, we have to read the payload before returning.
     */
    if (length > sizeof(payload_buf))
    {
        err = -EMSGSIZE;
    }

    /* Truncate payload until it fits in the payload buffer. */
    while (length > sizeof(payload_buf))
    {
        ret = mqtt_read_publish_payload_blocking(
            p_client, payload_buf, (length - sizeof(payload_buf)));
        if (ret == 0)
        {
            return -EIO;
        }
        else if (ret < 0)
        {
            return ret;
        }

        length -= ret;
    }

    ret = mqtt_readall_publish_payload(p_client, payload_buf, length);
    if (ret)
    {
        return ret;
    }

    return err;
}

/**@brief Function to print strings without null-termination
 *
 * @param[in] prefix String to print
 */
static void data_print(uint8_t * prefix, uint8_t * data, size_t len)
{
    char buf[len + 1];

    memcpy(buf, data, len);
    buf[len] = 0;
    LOG_INF("%s%s", (char *)prefix, (char *)buf);
}

/**@brief MQTT client event handler
 *
 * @param[in] p_client Pointer to MQTT client structure
 * @param[in] p_evt    Pointer to MQTT event structure
 */
static void mqtt_evt_handler(struct mqtt_client * const p_client,
                             const struct mqtt_evt * p_evt)
{
    int err;

    switch (p_evt->type)
    {
        case MQTT_EVT_CONNACK:
        {
            LOG_INF("MQTT client connected");
            err = subscribe(p_client);
            if (err < 0)
            {
                LOG_ERR("Failed to subscribe to topic, error: %d", err);
            }
            break;
        }

        case MQTT_EVT_DISCONNECT:
        {
            LOG_INF("MQTT client disconnected");
            break;
        }

        case MQTT_EVT_PUBLISH:
        {
            LOG_INF("MQTT PUBLISH received");

            /* Send acknowledgement to the broker, if QoS1 publish message is received. */
            if (p_evt->param.publish.message.topic.qos == MQTT_QOS_1_AT_LEAST_ONCE)
            {
                const struct mqtt_puback_param ack = {
                    .message_id = p_evt->param.publish.message_id
                };

                /* Send acknowledgement. */
                err = mqtt_publish_qos1_ack(p_client, &ack);
                if (err != 0)
                {
                    LOG_ERR("Failed to send MQTT ACK, error: %d", err);
                }
            }

            /* Get the payload of the received message. */
            err = get_received_payload(p_client, p_evt->param.publish.message.payload.len);

            /* Successfully extracted the payload. */
            if (err >= 0)
            {
                data_print("Payload: ", payload_buf, p_evt->param.publish.message.payload.len);

                /* Handling commands received over MQTT */
                if (strncmp((char *)payload_buf,
                            CONFIG_TURN_LED_ON_CMD,
                            sizeof(CONFIG_TURN_LED_ON_CMD) - 1) == 0)
                {
                    dk_set_led_on(LED_CONTROL_OVER_MQTT);
                }
                else if (strncmp((char *)payload_buf,
                                 CONFIG_TURN_LED_OFF_CMD,
                                 sizeof(CONFIG_TURN_LED_OFF_CMD) - 1) == 0)
                {
                    dk_set_led_off(LED_CONTROL_OVER_MQTT);
                }
                else
                {
                    LOG_ERR("Unknown command: %s", (char *)payload_buf);
                }
            }
            else if (err == -EMSGSIZE)
            {
                LOG_ERR("Payload too large: %d bytes", p_evt->param.publish.message.payload.len);
                LOG_INF("Maximum payload size: %d bytes", CONFIG_MQTT_PAYLOAD_BUFFER_SIZE);
            }
            else
            {
                LOG_ERR("Failed to extract payload, error: %d", err);

                /* Disconnect the client if we failed to extract the payload. */
                err = mqtt_disconnect(p_client);
                if (err)
                {
                    LOG_ERR("Failed to disconnect MQTT client, error: %d", err);
                }
            }
            break;

        }

        case MQTT_EVT_PUBACK:
            if (p_evt->result != 0)
            {
                LOG_ERR("MQTT PUBACK error: %d", p_evt->result);
                break;
            }

            LOG_INF("PUBACK packet id: %u", p_evt->param.puback.message_id);
            break;

        case MQTT_EVT_SUBACK:
            if (p_evt->result != 0)
            {
                LOG_ERR("MQTT SUBACK error: %d", p_evt->result);
                break;
            }

            LOG_INF("SUBACK packet id: %u", p_evt->param.suback.message_id);
            break;

        case MQTT_EVT_PINGRESP:
            if (p_evt->result != 0)
            {
                LOG_ERR("MQTT PINGRESP error: %d", p_evt->result);
            }
            break;

        default:
            LOG_INF("Unhandled MQTT event type: %d", p_evt->type);
            break;
    }
}

/**@brief Resolves the configured hostname and
 * initializes the MQTT broker structure
 */
static int broker_init(void)
{
    int err;
    struct addrinfo * result;
    struct addrinfo * addr;
    struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM
    };

    err = getaddrinfo(CONFIG_MQTT_BROKER_HOSTNAME, NULL, &hints, &result);
    if (err)
    {
        LOG_ERR("getaddrinfo failed: %d", err);
        return -ECHILD;
    }

    addr = result;

    /* Look for address of the broker. */
    while (addr != NULL)
    {
        /* IPv4 Address. */
        if (addr->ai_addrlen == sizeof(struct sockaddr_in))
        {
            struct sockaddr_in * broker4 =
                ((struct sockaddr_in *)&broker);
            char ipv4_addr[NET_IPV4_ADDR_LEN];

            broker4->sin_addr.s_addr =
                ((struct sockaddr_in *)addr->ai_addr)
                ->sin_addr.s_addr;
            broker4->sin_family = AF_INET;
            broker4->sin_port = htons(CONFIG_MQTT_BROKER_PORT);

            inet_ntop(AF_INET, &broker4->sin_addr.s_addr,
                      ipv4_addr, sizeof(ipv4_addr));
            LOG_INF("IPv4 Address found %s", (char *)(ipv4_addr));

            break;
        }
        else
        {
            LOG_ERR("ai_addrlen = %u should be %u or %u",
                    (unsigned int)addr->ai_addrlen,
                    (unsigned int)sizeof(struct sockaddr_in),
                    (unsigned int)sizeof(struct sockaddr_in6));
        }

        addr = addr->ai_next;
    }

    /* Free the address. */
    freeaddrinfo(result);

    return err;
}

/* Function to get the client id */
static const uint8_t * client_id_get(void)
{
    static uint8_t client_id[MAX(sizeof(CONFIG_MQTT_CLIENT_ID),
                                 CLIENT_ID_LEN)];

    if (strlen(CONFIG_MQTT_CLIENT_ID) > 0)
    {
        snprintf(client_id, sizeof(client_id), "%s",
                 CONFIG_MQTT_CLIENT_ID);
        goto exit;
    }

    char imei_buf[CGSN_RESPONSE_LENGTH + 1];
    int err;

    err = nrf_modem_at_cmd(imei_buf, sizeof(imei_buf), "AT+CGSN");
    if (err)
    {
        LOG_ERR("Failed to obtain IMEI, error: %d", err);
        goto exit;
    }

    imei_buf[IMEI_LEN] = '\0';

    snprintf(client_id, sizeof(client_id), "nrf-%.*s", IMEI_LEN, imei_buf);

exit:
    LOG_DBG("client_id = %s", (char *)(client_id));

    return client_id;
}

/**@brief Initialize the MQTT client structure
 *
 * @param[in] p_client Pointer to MQTT client structure
 */
int client_init(struct mqtt_client * p_client)
{
    int err;

    mqtt_client_init(p_client);

    /* Set MQTT broker details. */
    err = broker_init();
    if (err != 0)
    {
        LOG_ERR("Failed to initialize broker connection, error: %d", err);
        return err;
    }

    /* MQTT client configuration */
    p_client->broker = &broker;
    p_client->evt_cb = mqtt_evt_handler;
    p_client->client_id.utf8 = client_id_get();
    p_client->client_id.size = strlen(client_id_get());
    p_client->password = NULL;
    p_client->user_name = NULL;
    p_client->protocol_version = MQTT_VERSION_3_1_1;

    /* MQTT buffers configuration */
    p_client->rx_buf = rx_buffer;
    p_client->rx_buf_size = sizeof(rx_buffer);
    p_client->tx_buf = tx_buffer;
    p_client->tx_buf_size = sizeof(tx_buffer);

    /* Enable TLS. */
    LOG_INF("Enabling TLS");
    p_client->transport.type = MQTT_TRANSPORT_SECURE;

    struct mqtt_sec_config * tls_config = &(p_client->transport).tls.config;
    static sec_tag_t sec_tag_list[] = {
        CONFIG_MQTT_TLS_SEC_TAG,
    };

    /* Set the security configuration for the MQTT client. */
    tls_config->peer_verify = CONFIG_MQTT_TLS_PEER_VERIFY;
    tls_config->cipher_count = 0;
    tls_config->cipher_list = NULL;
    tls_config->sec_tag_count = ARRAY_SIZE(sec_tag_list);
    tls_config->sec_tag_list = sec_tag_list;
    tls_config->session_cache = IS_ENABLED(CONFIG_MQTT_TLS_SESSION_CACHING) ?
                                TLS_SESSION_CACHE_ENABLED :
                                TLS_SESSION_CACHE_DISABLED;
    tls_config->hostname = CONFIG_MQTT_BROKER_HOSTNAME;
    tls_config->cert_nocopy = TLS_CERT_NOCOPY_NONE;
    tls_config->set_native_tls = 0;

    return err;
}

/**@brief Initialize the file descriptor structure used by poll.
 *
 * @param[in] p_client Pointer to MQTT client structure
 * @param[in] p_fds    Pointer to pollfd structure
 */
int fds_init(struct mqtt_client * p_client, struct pollfd * p_fds)
{
    if (p_client->transport.type == MQTT_TRANSPORT_NON_SECURE)
    {
        p_fds->fd = p_client->transport.tcp.sock;
    }
    else if (p_client->transport.type == MQTT_TRANSPORT_SECURE)
    {
        p_fds->fd = p_client->transport.tls.sock;
    }
    else
    {
        return -ENOTSUP;
    }

    p_fds->events = POLLIN;

    return 0;
}

/**@brief Function to publish data on the configured topic
 *
 * @param[in] p_client Pointer to MQTT client structure
 * @param[in] qos      MQTT QoS
 * @param[in] p_data   Pointer to data to be published
 * @param[in] len      Length of data to be published
 */
int data_publish(struct mqtt_client * p_client, enum mqtt_qos qos, uint8_t * p_data, size_t len)
{
    int err;

    /* Define MQTT message */
    const struct mqtt_publish_param param = {
        .message.topic.qos = qos,
        .message.topic.topic.utf8 = CONFIG_MQTT_PUB_TOPIC,
        .message.topic.topic.size = strlen(CONFIG_MQTT_PUB_TOPIC),
        .message.payload.data = p_data,
        .message.payload.len = len,
        .message_id = sys_rand32_get(),
        .dup_flag = 0,
        .retain_flag = 0
    };

    /* Publish MQTT message */
    LOG_INF("Publishing: %s to topic: %s", (char *)p_data, CONFIG_MQTT_PUB_TOPIC);
    err = mqtt_publish(p_client, &param);
    if (err)
    {
        LOG_ERR("Failed to publish message, error: %d", err);
        return err;
    }
    return err;
}

/**@brief Function to store certificate in the modem if it does not exist.
 *
 * @note If the certificate already exists, the function checks if the certificate
 *       in the modem matches the certificate in the application.
 */
int certificate_provision()
{
    int err;
    bool exists;

    /* Check if the certificate already exists in the modem. */
    err = modem_key_mgmt_exists(CONFIG_MQTT_TLS_SEC_TAG,
                                MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN,
                                &exists);

    if (err != 0)
    {
        LOG_ERR("Failed to check certificate, error: %d", err);
    }

    if (exists)
    {
        LOG_INF("Certificate already exists");

        LOG_INF("Comparing credentials in modem with the certificate");
        err = modem_key_mgmt_cmp(CONFIG_MQTT_TLS_SEC_TAG,
                                 MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN,
                                 CA_CERTIFICATE,
                                 strlen(CA_CERTIFICATE));

        if (err == 0)
        {
            LOG_INF("Credentials in modem match the certificate");
        }
        else if (err == 1)
        {
            LOG_INF("Credentials in modem do not match the certificate");
            LOG_INF("Deleting the certificate from the modem");
            err = modem_key_mgmt_delete(CONFIG_MQTT_TLS_SEC_TAG,
                                        MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN);
            if (err != 0)
            {
                LOG_ERR("Failed to delete certificate, error: %d", err);
                return err;
            }

            /* Write the certificate to the modem. */
            err = modem_key_mgmt_write(CONFIG_MQTT_TLS_SEC_TAG,
                                       MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN,
                                       CA_CERTIFICATE,
                                       strlen(CA_CERTIFICATE));
            if (err != 0)
            {
                LOG_ERR("Failed to provision certificate, error: %d", err);
                return err;
            }
            LOG_INF("Certificate provisioned successfully");
        }
        else
        {
            LOG_ERR("Failed to compare certificate, error: %d", err);
        }
    }
    else
    {
        LOG_INF("Certificate does not exist");

        /* Write the certificate to the modem. */
        err = modem_key_mgmt_write(CONFIG_MQTT_TLS_SEC_TAG,
                                   MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN,
                                   CA_CERTIFICATE,
                                   strlen(CA_CERTIFICATE));
        if (err != 0)
        {
            LOG_ERR("Failed to provision certificate, error: %d", err);
            return err;
        }
        LOG_INF("Certificate provisioned successfully");
    }
    return err;
}
