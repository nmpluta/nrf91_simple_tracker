#include <stdio.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <dk_buttons_and_leds.h>
#include <modem/nrf_modem_lib.h>
#include <modem/lte_lc.h>

LOG_MODULE_REGISTER(nrf91_simple_tracker, LOG_LEVEL_INF);

#define STATUS_LED DK_LED1

static void button_handler(uint32_t button_state, uint32_t has_changed);
static void lte_handler(const struct lte_lc_evt * const evt);

/* Semaphore blocking the main thread until LTE connection is established */
K_SEM_DEFINE(lte_connected, 0, 1);

int main(void)
{
    int err;

    LOG_INF("Simple Tracker Application");

    err = dk_buttons_init(button_handler);
    if (err != 0)
    {
        LOG_INF("dk_buttons_init, error: %d\n", err);
        return err;
    }

    err = dk_leds_init();
    if (err != 0)
    {
        LOG_INF("dk_leds_init, error: %d\n", err);
        return err;
    }

	err = nrf_modem_lib_init();

	if (err == 0)
	{
		LOG_INF("Modem library initialized");
	}
	else if (err > 0) {
		LOG_INF("Modem firmaware update is performed");
	}
	else
	{
		LOG_ERR("Failed to initialize modem library, error: %d", err);
		return err;
	}

    err = lte_lc_init_and_connect_async(lte_handler);
    if (err != 0)
    {
        LOG_INF("lte_lc_init_and_connect_async, error: %d\n", err);
        return err;
    }

	LOG_INF("Connecting to LTE network");

    /* Wait for the semaphore to be released */
    k_sem_take(&lte_connected, K_FOREVER);

    while (1)
    {
        /* Toggle status LED*/
        dk_set_led(STATUS_LED, 1);
        k_sleep(K_MSEC(1000));
        dk_set_led(STATUS_LED, 0);
    }

    return 0;
}

static void button_handler(uint32_t button_state, uint32_t has_changed)
{
    int err;

    switch (has_changed)
    {
        case DK_BTN1_MSK:
            LOG_INF("Button 1 pressed");
            break;
        case DK_BTN2_MSK:
            LOG_INF("Button 2 pressed");
            break;
        default:
            LOG_INF("Invalid button");
            break;
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
            LOG_INF("eDRX parameter update: eDRX: %d, PTW: %d",
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

