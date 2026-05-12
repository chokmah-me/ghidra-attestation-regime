// Minimal main for TIM_TimeBase example
// Links against STM32CubeF4 HAL sources in C:\Tools\STM32CubeF4

#include "stm32f4xx_hal.h"

TIM_HandleTypeDef htim;

void SystemClock_Config(void) {
    // Configure system clock (from STM32CubeF4 template)
}

void MX_TIM2_Init(void) {
    TIM_MasterConfigTypeDef sMasterConfig = {0};

    htim.Instance = TIM2;
    htim.Init.Prescaler = 9999;
    htim.Init.CounterMode = TIM_COUNTERMODE_UP;
    htim.Init.Period = 9999;
    htim.Init.ClockDivision = TIM_CLOCKDIVISION_DIV1;
    HAL_TIM_Base_Init(&htim);

    sMasterConfig.MasterOutputTrigger = TIM_TRGO_UPDATE;
    sMasterConfig.MasterSlaveMode = TIM_MASTERSLAVEMODE_DISABLE;
    HAL_TIMEx_MasterConfigSynchronization(&htim, &sMasterConfig);
}

void HAL_TIM_Base_MspInit(TIM_HandleTypeDef* htim_base) {
    if(htim_base->Instance == TIM2) {
        __HAL_RCC_TIM2_CLK_ENABLE();
    }
}

int main(void) {
    HAL_Init();
    SystemClock_Config();
    MX_TIM2_Init();

    HAL_TIM_Base_Start(&htim);

    while(1) {
        // Busy loop
    }

    return 0;
}

void SysTick_Handler(void) {
    HAL_IncTick();
}
