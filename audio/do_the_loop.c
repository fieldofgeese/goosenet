#include <stdio.h>
#include <math.h>

#define MINIAUDIO_IMPLEMENTATION
#define MA_NO_ENCODING
#define MA_NO_DECODING
#define MA_NO_WAV
#define MA_NO_FLAC
#define MA_NO_MP3
#include "miniaudio.h"

void data_callback(ma_device *device, void *output, const void *input, ma_uint32 frame_count) {
    memcpy(output, input, ma_get_bytes_per_sample(device->playback.format) * device->playback.channels * frame_count);
}

int read_int_from_stdin(int *output) {
    char buf[16] = {0};
    if (fgets(buf, 16, stdin) == NULL)
        return 1;
    *output = atoi(buf);
    return 0;
}

int main() {
    // Initialize miniaudio
    ma_context context;
    if (ma_context_init(NULL, 0, NULL, &context) != MA_SUCCESS) {
        fputs("miniaudio: Failed to initialize context", stderr);
        goto return_normal;
    }

    // Get list of playback and capture devices
    ma_device_info* playback_infos = NULL;
    ma_uint32       playback_count = 0;
    ma_device_info* capture_infos = NULL;
    ma_uint32       capture_count = 0;
    if (ma_context_get_devices(&context, &playback_infos, &playback_count, &capture_infos, &capture_count) != MA_SUCCESS) {
        fputs("miniaudio: Failed to get devices", stderr);
        goto context_cleanup;
    }

    // Select input device
    puts("Input devices:");
    for (ma_uint32 i = 0; i < capture_count; ++i) {
        printf("  %d - %s\n", i, capture_infos[i].name);
    }
    printf("Select input device: ");

    int input_choice = 0;
    if (read_int_from_stdin(&input_choice) != 0 || (input_choice < 0 || input_choice >= capture_count)) {
        fputs("Give me some reasonable input please (^o.o^)", stderr);
        goto context_cleanup;
    }

    puts("");

    // Select output device
    puts("Output devices:");
    for (ma_uint32 i = 0; i < playback_count; ++i) {
        printf("  %d - %s\n", i, playback_infos[i].name);
    }
    printf("Select output device: ");

    int output_choice = 0;
    if (read_int_from_stdin(&output_choice) != 0 || (output_choice < 0 || output_choice >= playback_count)) {
        fputs("Give me some reasonable output please (^o.o^)", stderr);
        goto context_cleanup;
    }

    // Initialize devices
    ma_device_config config   = ma_device_config_init(ma_device_type_duplex);
    config.playback.pDeviceID = &playback_infos[output_choice].id;
    config.playback.format    = ma_format_f32;
    config.playback.channels  = 2;
    config.capture.pDeviceID  = &capture_infos[input_choice].id;
    config.capture.format     = ma_format_f32;
    config.capture.channels   = 2;
    config.sampleRate         = 48000;
    config.dataCallback       = data_callback;
    config.pUserData          = NULL;

    ma_device device;
    if (ma_device_init(&context, &config, &device) != MA_SUCCESS) {
        fputs("miniaudio: Failed to init device", stderr);
        goto device_cleanup;
    }

    // Actually play the input/output
    ma_device_start(&device);
    printf("\nNow playing, enter anything to exit: ");
    fgetc(stdin);
    ma_device_stop(&device);

device_cleanup:
    ma_device_uninit(&device);
context_cleanup:
    ma_context_uninit(&context);
return_normal:
    return 0;
}
