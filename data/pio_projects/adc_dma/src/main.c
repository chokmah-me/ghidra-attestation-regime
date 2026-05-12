// Minimal main for ADC_RegularConversion_DMA example
// Links against STM32CubeF4 HAL sources in C:\Tools\STM32CubeF4

#include "stm32f4xx_hal.h"

ADC_HandleTypeDef hadc1;
DMA_HandleTypeDef hdma_adc1;
uint32_t adc_value;

void SystemClock_Config(void) {
    // Configure system clock
}

void MX_ADC1_Init(void) {
    ADC_ChannelConfTypeDef sConfig = {0};

    hadc1.Instance = ADC1;
    hadc1.Init.ClockPrescaler = ADC_CLOCK_SYNC_PCLK_DIV4;
    hadc1.Init.Resolution = ADC_RESOLUTION_12B;
    hadc1.Init.ScanConvMode = DISABLE;
    hadc1.Init.ContinuousConvMode = DISABLE;
    hadc1.Init.DiscontinuousConvMode = DISABLE;
    hadc1.Init.ExternalTrigConv = ADC_SOFTWARE_START;
    hadc1.Init.DataAlign = ADC_DATAALIGN_RIGHT;
    hadc1.Init.NbrOfConversion = 1;
    HAL_ADC_Init(&hadc1);

    sConfig.Channel = ADC_CHANNEL_0;
    sConfig.Rank = 1;
    sConfig.SamplingTime = ADC_SAMPLETIME_112CYCLES;
    HAL_ADC_ConfigChannel(&hadc1, &sConfig);
}

void MX_DMA_Init(void) {
    hdma_adc1.Instance = DMA2_Stream0;
    hdma_adc1.Init.Channel = DMA_CHANNEL_0;
    hdma_adc1.Init.Direction = DMA_PERIPH_TO_MEMORY;
    hdma_adc1.Init.PeriphInc = DMA_PINC_DISABLE;
    hdma_adc1.Init.MemInc = DMA_MINC_ENABLE;
    hdma_adc1.Init.PeriphDataAlignment = DMA_PDATAALIGN_WORD;
    hdma_adc1.Init.MemDataAlignment = DMA_MDATAALIGN_WORD;
    hdma_adc1.Init.Mode = DMA_CIRCULAR;
    hdma_adc1.Init.Priority = DMA_PRIORITY_MEDIUM;
    HAL_DMA_Init(&hdma_adc1);

    __HAL_LINKDMA(&hadc1, DMA_Handle, hdma_adc1);
}

void HAL_ADC_MspInit(ADC_HandleTypeDef* hadc) {
    if(hadc->Instance == ADC1) {
        __HAL_RCC_ADC1_CLK_ENABLE();
        __HAL_RCC_GPIOA_CLK_ENABLE();
    }
}

int main(void) {
    HAL_Init();
    SystemClock_Config();

    MX_DMA_Init();
    MX_ADC1_Init();

    HAL_ADC_Start_DMA(&hadc1, &adc_value, 1);

    while(1) {
        // Monitor ADC value via DMA
    }

    return 0;
}

void SysTick_Handler(void) {
    HAL_IncTick();
}
