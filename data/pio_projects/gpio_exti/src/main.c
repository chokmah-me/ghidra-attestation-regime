// Minimal main for GPIO_EXTI example
// Links against STM32CubeF4 HAL sources in C:\Tools\STM32CubeF4

#include "stm32f4xx_hal.h"

void SystemClock_Config(void) {
    // Configure system clock
}

void MX_GPIO_Init(void) {
    GPIO_InitTypeDef GPIO_InitStruct = {0};

    __HAL_RCC_GPIOA_CLK_ENABLE();
    __HAL_RCC_GPIOD_CLK_ENABLE();

    // PA0 as EXTI input (button)
    GPIO_InitStruct.Pin = GPIO_PIN_0;
    GPIO_InitStruct.Mode = GPIO_MODE_IT_FALLING;
    GPIO_InitStruct.Pull = GPIO_PULLUP;
    HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);

    HAL_NVIC_SetPriority(EXTI0_IRQn, 2, 0);
    HAL_NVIC_EnableIRQ(EXTI0_IRQn);
}

void HAL_GPIO_EXTI_Callback(uint16_t GPIO_Pin) {
    if (GPIO_Pin == GPIO_PIN_0) {
        // Button pressed - toggle LED
        HAL_GPIO_TogglePin(GPIOD, GPIO_PIN_12);
    }
}

int main(void) {
    HAL_Init();
    SystemClock_Config();
    MX_GPIO_Init();

    while(1) {
        // Wait for external interrupt
    }

    return 0;
}

void EXTI0_IRQHandler(void) {
    HAL_GPIO_EXTI_IRQHandler(GPIO_PIN_0);
}

void SysTick_Handler(void) {
    HAL_IncTick();
}
