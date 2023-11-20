#include <stdio.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/mqtt.h>

#include <dk_buttons_and_leds.h>
#include <modem/nrf_modem_lib.h>
#include <modem/lte_lc.h>

#include "mqtt_connection.h"

#define STATUS_LED DK_LED1

LOG_MODULE_REGISTER(nrf91_simple_tracker, LOG_LEVEL_INF);

/* Semaphore blocking the main thread until LTE connection is established */
K_SEM_DEFINE(lte_connected, 0, 1);

static void button_handler(uint32_t button_state, uint32_t has_changed);
static void lte_handler(const struct lte_lc_evt * const evt);
static int modem_configure(void);

/* The mqtt client struct */
static struct mqtt_client client;
/* File descriptor */
static struct pollfd fds;

int main(void)
{
    int err;
    uint32_t connect_attempt = 0;

    LOG_INF("Simple Tracker Application");

    err = dk_buttons_init(button_handler);
    if (err != 0)
    {
        LOG_ERR("dk_buttons_init, error: %d\n", err);
        return err;
    }

    err = dk_leds_init();
    if (err != 0)
    {
        LOG_ERR("dk_leds_init, error: %d\n", err);
        return err;
    }

    err = modem_configure();
    if (err != 0)
    {
        LOG_ERR("modem_configure, error: %d\n", err);
        return err;
    }

    LOG_INF("Initializing MQTT client");
    err = client_init(&client);
    if (err != 0)
    {
        LOG_ERR("client_init, error: %d\n", err);
        return err;
    }

do_connect:
    if (connect_attempt++ > 0)
    {
        LOG_INF("Reconnecting in %d seconds...",
                CONFIG_MQTT_RECONNECT_DELAY_S);
        k_sleep(K_SECONDS(CONFIG_MQTT_RECONNECT_DELAY_S));
    }
    err = mqtt_connect(&client);
    if (err)
    {
        LOG_ERR("mqtt_connect, error: %d", err);
        goto do_connect;
    }

    err = fds_init(&client, &fds);
    if (err)
    {
        LOG_ERR("fds_init, error: %d", err);
        return 0;
    }

    while (1)
    {
        err = poll(&fds, 1, mqtt_keepalive_time_left(&client));
        if (err < 0)
        {
            LOG_ERR("poll, error: %d", errno);
            break;
        }

        err = mqtt_live(&client);
        if ((err != 0) && (err != -EAGAIN))
        {
            LOG_ERR("mqtt_live, error: %d", err);
            break;
        }

        if ((fds.revents & POLLIN) == POLLIN)
        {
            err = mqtt_input(&client);
            if (err != 0)
            {
                LOG_ERR("mqtt_input, error: %d", err);
                break;
            }
        }

        if ((fds.revents & POLLERR) == POLLERR)
        {
            LOG_ERR("POLLERR");
            break;
        }

        if ((fds.revents & POLLNVAL) == POLLNVAL)
        {
            LOG_ERR("POLLNVAL");
            break;
        }
    }

    LOG_INF("Disconnecting MQTT client");

    err = mqtt_disconnect(&client);
    if (err)
    {
        LOG_ERR("Could not disconnect MQTT client: %d", err);
    }
    goto do_connect;

    return 0;
}

static void button_handler(uint32_t button_state, uint32_t has_changed)
{
    switch (has_changed)
    {
        case DK_BTN1_MSK:
        {
            if (button_state & DK_BTN1_MSK)
            {
                LOG_INF("Button 1 pressed");

                char * data = "Button 1 pressed";
                int err = data_publish(&client, MQTT_QOS_1_AT_LEAST_ONCE, data, strlen(data));
                if (err != 0)
                {
                    LOG_ERR("Failed to publish message");
                    return;
                }
            }
            break;
        }
        case DK_BTN2_MSK:
        {
            if (button_state & DK_BTN2_MSK)
            {
                LOG_INF("Button 2 pressed");
                char * data = "Button 2 pressed";
                int err = data_publish(&client, MQTT_QOS_1_AT_LEAST_ONCE, data, strlen(data));
                if (err != 0)
                {
                    LOG_ERR("Failed to publish message");
                    return;
                }
            }
            break;
        }
        default:
        {
            LOG_INF("Invalid button");
            break;
        }
    }
}

static void lte_handler(const struct lte_lc_evt * const evt)
{
    switch (evt->type)
    {
        case LTE_LC_EVT_NW_REG_STATUS:
        {
            if (evt->nw_reg_status == LTE_LC_NW_REG_REGISTERED_HOME ||
                evt->nw_reg_status == LTE_LC_NW_REG_REGISTERED_ROAMING)
            {
                LOG_INF("Network registration status: %s",
                        evt->nw_reg_status == LTE_LC_NW_REG_REGISTERED_HOME ?
                        "Connected - home network" : "Connected - roaming");
                k_sem_give(&lte_connected);
            }
            else
            {
                LOG_INF("Network registration status: %s",
                        evt->nw_reg_status == LTE_LC_NW_REG_SEARCHING ?
                        "Searching..." : "Disconnected");
            }
            break;
        }
        case LTE_LC_EVT_PSM_UPDATE:
        {
            LOG_INF("PSM parameter update: TAU: %d, Active time: %d",
                    evt->psm_cfg.tau, evt->psm_cfg.active_time);
            break;
        }
        case LTE_LC_EVT_EDRX_UPDATE:
        {
            LOG_INF("eDRX parameter update: eDRX: %.2f , PTW: %.2f",
                    evt->edrx_cfg.edrx, evt->edrx_cfg.ptw);
            break;
        }
        case LTE_LC_EVT_RRC_UPDATE:
        {
            LOG_INF("RRC mode: %s", evt->rrc_mode == LTE_LC_RRC_MODE_IDLE ? "Idle" : "Connected");
            break;
        }
        default:
            break;
    }
}

static int modem_configure(void)
{
    int err;

    err = nrf_modem_lib_init();
    if (err == 0)
    {
        LOG_INF("Modem library initialized");
    }
    else if (err > 0)
    {
        LOG_INF("Modem firmaware update is performed");
    }
    else
    {
        LOG_ERR("Failed to initialize modem library, error: %d", err);
        return err;
    }

    err = certificate_provision();
    if (err)
    {
        LOG_ERR("Failed to provision certificate, error: %d", err);
        return err;
    }

    LOG_INF("Connecting to LTE network");

    err = lte_lc_init_and_connect_async(lte_handler);
    if (err != 0)
    {
        LOG_ERR("lte_lc_init_and_connect_async, error: %d\n", err);
        return err;
    }

    /* Wait for the semaphore to be released */
    k_sem_take(&lte_connected, K_FOREVER);
    dk_set_led_on(STATUS_LED);

    LOG_INF("Connected to LTE network");

    return 0;
}
