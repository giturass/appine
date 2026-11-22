# Mobile GPU support for Alpine and Debian guests

On the Samsung Galaxy S23 (Adreno 740), Google Pixel 8 (Mali-G715) and Google Pixel 11 Pro (PowerVR C-Series CXTP-48-1536 MC1), an unprivileged Alpine or Debian shell can run headless Vulkan buffer compute using the distribution's unmodified Mesa Venus driver. Appine provides the DRM render node and the Android renderer. The loader discovers the driver through the distribution's normal ICD manifest.

## Run it

Enable **Vulkan GPU** under **Settings → Debugging** and confirm the restart. The toggle is off by default because vendor Vulkan driver compatibility varies by device.

Install the packages as the guest administrator. In Alpine use `apk add mesa-vulkan-virtio vulkan-tools`. In Debian use `apt-get install mesa-vulkan-drivers vulkan-tools`. Then run `vulkaninfo --summary` from the regular user's shell. Look for `Virtio-GPU Venus (Adreno (TM) 740)`, `PHYSICAL_DEVICE_TYPE_INTEGRATED_GPU` and `DRIVER_ID_MESA_VENUS`. If the distribution also installed Lavapipe, the tool lists a second device named llvmpipe. Headless runs may print warnings about the display.

For a short command that requires the hardware GPU, prefix the command with `appine-gpu`. For example, `appine-gpu vulkaninfo --summary` lists the Venus device. The launcher sets `VK_DRIVER_FILES` to the packaged Venus manifest for that invocation. Run `vulkaninfo --summary` directly to list all installed drivers. Appine installs the launcher in new and existing guests when starting with Vulkan GPU enabled.

The tested workload uses ordinary storage buffers, a compute shader and a fence. Window presentation, OpenGL, OpenCL, external image sharing and PRIME fd exchange require additional interfaces.

## How a submission reaches the phone

1. When Vulkan GPU is enabled in Settings, the private Android `:venus` service tests Vulkan export, reimport, GPU copy, fence completion and CPU readback at machine startup. Appine registers `/dev/dri/renderD128` (226:128, mode 0666) and the platform device in sysfs when the probe and mapper initialization succeed. When the toggle is off (the default) or in the CLI, Appine starts without a renderer and skips the `:venus` probe. Both packaged libdrm versions inspect `/sys/dev/char/226:128/device/drm`, its sibling `subsystem` link and the device's `uevent`.
2. Each open file description has a Venus context, a private handle table and its own command connection. Duplicated descriptors share them. The kernel implements the DRM version, parameter, capset, context, blob, map, resource-info, execbuffer and GEM-close requests. The two packaged ICDs emulate sync objects with output fences, poll and fd duplication. Appine returns the decoder's Venus capset and reports zero PRIME, cross-device and kernel syncobj support. [Mesa Venus documentation](https://docs.mesa3d.org/drivers/venus.html) · [Kernel ioctl implementation](../core/kernel/src/syscall/gpu.rs)
3. A dedicated service thread decodes each connection using virglrenderer 1.3.0 and the system Vulkan loader. The service is nonexported and runs in a separate process under Appine's ordinary Android UID. On the S23, a service using an Android isolated UID received `EACCES` when the vendor Vulkan implementation opened its GPU device. [Android service](../android/app/src/main/java/io/github/mthli/appine/GpuService.kt) · [Renderer worker](../hosts/android/gpu/worker.c)
4. Venus command and reply rings use shared memory. For host-visible ordinary buffer allocations, the patched decoder requests an exportable Android Hardware Buffer BLOB. The application receives its native handle over a Unix socket, checks its format, size, memory type and physical-device UUID, imports it on a second logical device, and maps coherent memory into the guest page table. If that import cannot provide a coherent CPU mapping, Appine probes the opposite direction. On the Pixel 8 the machine process maps its original coherent allocation and exports it to the renderer, which imports it for GPU use. A per-context socket handles allocation requests from Venus rings. The guest sees the CPU mapping properties at the memory index used for GPU binding. The decoder hides host-visible memory types that the mapper cannot keep coherent. This path supports multiple buffers bound at different offsets in one allocation. [Decoder patch](../hosts/android/gpu/android-blob.patch) · [Mapper](../hosts/android/gpu/mapper.c) · [Vulkan device memory](https://docs.vulkan.org/spec/latest/chapters/memory.html)
5. A guest VMA keeps its mapping through GEM close, descriptor close and fork. Execbuffer retains its referenced buffers until the ring fence retires. Fence waits and driver cleanup run outside the big kernel lock. Context shutdown stops the command rings and drains outstanding GPU work before destroying Vulkan objects. [Host lifetimes](../hosts/android/src/gpu.rs) · [Guest mappings](../core/kernel/src/mm.rs)

## Measurements on the Galaxy S23

SM-S9110, firmware `S9110ZCS8FZJ1`, Android API 36, 4,096-byte host pages (the firmware reports `ro.product.cpu.pagesize.max=4096`), Adreno 740, Vulkan 1.3.128, vendor driver `0x802a4001`. The native probe ran with ordinary app privileges. DMA-BUF failed at the missing `VK_EXT_external_memory_dma_buf` extension. Generic opaque-fd export required a dedicated resource. Its dedicated-buffer control passed. Android Hardware Buffer export/import reported feature bits `0x6` and passed a two-buffer, two-device copy with all 1,024 words verified.

The guest tests ran with Tier 1 in independent temporary stores as UID 1000. Both the packaged `vulkaninfo --summary` and the compute executable ran without driver-selection or debug environment overrides. The sample uploads 256 KiB, dispatches 1,024 workgroups, waits for a fence and checks all 65,536 output words. End-to-end time includes loader, device and pipeline setup through final verification. These are individual measured runs.

| Guest | ICD manifest | Mesa | Upload | Queue submit | Fence wait | Invalidate and check | End to end |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| Alpine 3.24 | `virtio_icd.aarch64.json` | 26.1.6-r0 | 0.071 ms | 0.581 ms | 9.353 ms | 0.200 ms | 287.975 ms |
| Debian trixie | `virtio_icd.json` | 25.0.7-2+deb13u1 | 0.069 ms | 0.427 ms | 0.629 ms | 0.161 ms | 203.833 ms |

A separate comparison timed the same workload in fresh processes in a warmed guest, from Vulkan instance creation through result verification. With Lavapipe also installed, median time fell from 132 to 68 ms on Debian and from 106 to 56 ms on Alpine when the process selected only the Venus manifest. Each median covers 12 runs with the configuration order reversed between two guest starts. The comparison set `VK_DRIVER_FILES` directly and timed the compute program itself.

A second test on the debug APK timed each command from fork through process exit, including the launcher. After four warm-up runs, 12 runs per mode gave medians of 117.2 ms directly and 57.9 ms with `appine-gpu` on Debian, and 113.4 ms directly and 54.1 ms with the launcher on Alpine. All runs verified 65,536 words.

Both distributions also passed packaged discovery and the compute check against the R8-shrunk release APK. Both passed the shared-mapping test after GEM close, descriptor close and fork. With two concurrent clients, one process received SIGKILL after confirming its submitted fence was unsignaled. The shell stayed responsive, the survivor verified all words, and a fresh machine completed the same computation. The instrumentation checked the main process for leftover Venus shared mappings and retirement threads after shutdown.

Separate guest `strace` runs on the S23 release APK verified all 65,536 words in both distributions. Each trace showed five blob creations, five map ioctls and five GEM closes. Alpine made 43 execbuffer calls, duplicated a fence fd with `F_DUPFD_CLOEXEC` and observed `POLLIN` on the duplicate through `ppoll`. Debian made 26 execbuffer calls and completed this run without a `ppoll` call. Neither run issued a DRM syncobj or PRIME ioctl. The timing table uses the untraced runs.

On the API 37, 16,384-byte-page emulator, Goldfish GFXStream reported zero Android Hardware Buffer external-buffer features with both llvmpipe and host acceleration on an Apple M2 Pro. The negative test confirmed that the guest could start and both the render node and corresponding sysfs path were absent. A successful hardware-backed run with 16 KiB host pages remains unverified.

## Measurements on the Pixel 11 Pro

Firmware `CD1A.261005.003`, Android API 37, 4,096-byte host pages, Vulkan 1.4.317, vendor driver `0x696bd0`. The Android Hardware Buffer probe reported external-memory feature bits `0x6` and verified all 1,024 words after a two-device GPU copy. Both opaque-fd probes (ordinary and dedicated allocations) also passed. The DMA-BUF probe reported zero external-memory features for the tested buffer and stopped at the export capability check.

On the debug APK, both Tier 1 guests discovered `Virtio-GPU Venus (PowerVR C-Series CXTP-48-1536 MC1)` as UID 1000. Each verified all 65,536 output words in four runs: default driver discovery, Venus selected with `appine-gpu`, a surviving client after its peer was killed with an unsignaled fence, and a fresh guest start. Both also passed the shared-mapping lifetime and shutdown cleanup checks.

| Guest | Mesa | Default discovery | With `appine-gpu` |
| --- | --- | ---: | ---: |
| Alpine 3.24 | 26.1.6 | 258.0 ms | 84.3 ms |
| Debian trixie | 25.0.7-2+deb13u1 | 424.0 ms | 226.1 ms |

Each cell is one end-to-end measurement inside the compute program. The default invocation ran first, followed by the launcher invocation in the same guest.

## Measurements on the Pixel 8

Firmware `CP31.260623.005`, Android API 37, 4,096-byte host pages, Mali-G715, Vulkan 1.4.343, vendor driver `0xd803000`. The original Android Hardware Buffer probe reported import and export support (`0x6`), but the buffer exported from coherent type 0 could only be imported as noncoherent type 1 (mask `0x2`). The import size was 20,480 bytes for a 16,384-byte request. DMA-BUF reported import-only support (`0x4`), and both opaque-fd probes reported zero external-memory features for the tested buffer.

With the CPU mapping on the exporting device (type 0) and GPU commands on the importing device (type 1), the native probe verified all 1,024 words without explicit cache maintenance. The runtime uses the same direction across the machine process and the private renderer service. The probe selects the physical device and memory types at startup.

On the debug APK, Alpine 3.24 (Mesa 26.1.6) and Debian trixie (Mesa 25.0.7) both discovered `Virtio-GPU Venus (Mali-G715)` as UID 1000. Each verified 65,536 words with default discovery, with `appine-gpu`, after a concurrent client died with an unsignaled fence, and after a machine restart. Both passed the shared-mapping lifetime and shutdown checks. With the R8-shrunk release APK, both guests also passed the mapping lifetime test, discovered Venus and verified all 65,536 words with only the packaged Venus ICD selected.

Five runs of `GpuTest#distributionVenus` per distribution used the debug APK and a fresh Tier 1 guest store each time. As on the Pixel 11 Pro, the test ran `vulkaninfo --summary`, then the compute sample with default discovery, then the same sample with `appine-gpu`. Both invocations dispatched 1,024 workgroups on the Mali GPU and verified all 65,536 words. The fixed order gives the second invocation a warm guest, so the difference includes any warm-up effects.

| Guest | Discovery | Upload | Queue submit | Fence wait | Invalidate and check | End to end (min–max) |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Alpine 3.24 | Default | 0.385 | 3.797 | 7.505 | 44.524 | 644.3 (530.7–898.1) |
| Alpine 3.24 | `appine-gpu` | 0.217 | 2.891 | 2.589 | 35.816 | 275.0 (247.2–284.3) |
| Debian trixie | Default | 0.452 | 2.767 | 7.169 | 46.001 | 609.5 (530.3–680.5) |
| Debian trixie | `appine-gpu` | 0.313 | 2.564 | 2.662 | 41.129 | 252.8 (235.2–260.1) |

All times are medians in milliseconds, with the end-to-end range in parentheses. The compute program times Vulkan instance creation through CPU verification, including device and pipeline setup. With `appine-gpu`, the median fence wait was about 2.6 ms in both guests. Invalidating the mapped buffer and checking its 256 KiB on the guest CPU took 35.8 ms on Alpine and 41.1 ms on Debian.

## llama.cpp on Alpine 3.24

All four phones loaded Qwen2.5-Instruct Q4_0 with full Vulkan offload (25/25 layers at 0.5B and 29/29 at 1.5B). The same two prompts checked whether each GPU produced usable text with the default inference settings.

| Device | 0.5B · English-to-Chinese translation | 1.5B · Seven plus eight |
| --- | --- | --- |
| Pixel 11 Pro · PowerVR | Unrelated text and repeated question marks | Unrelated text |
| Pixel 8 · Mali-G715 | “一个GPU可以同时处理许多任务。” | Answered 15 correctly |
| Galaxy S23 · Adreno 740 | Shader link failed during warm-up | Shader link failed during warm-up |
| Galaxy S25 Ultra · Adreno 830 | 64 question marks | Unrelated text |

On the Galaxy S23, the CPU translated the sentence as “GPU可以并行处理许多任务。” and answered “十五” (15). With Vulkan, the Adreno driver logged `Failed to link shaders` and Venus then reported a command-stream error at `vkCmdBindPipeline`. Neither prompt produced a token. Disabling Flash Attention alone reproduced the failure on both models. The 0.5B translation also failed with `-fa off --no-warmup` at microbatch sizes 16 and 1. At size 1 the renderer process exited on SIGSEGV after the shader link error.

On the same S23 firmware, an Android-native build of llama.cpp b9564 ran the same prompts and GGUF files with the SPIR-V from Alpine's Vulkan package. The native CPU translated the sentence correctly and answered “15”. With 25/25 and 29/29 layers on Adreno 740, both native Vulkan runs aborted during warm-up while creating the `quantize_q8_1_x4` compute pipeline. The Adreno driver logged `Failed to link shaders` in each process. This reproduces the warm-up failure independently of Appine and Venus. The guest log does not identify the pipeline by name.

Disabling Flash Attention alone left both native runs failing at `quantize_q8_1_x4`. Setting `GGML_VK_DISABLE_INTEGER_DOT_PRODUCT=1` alone moved both failures to `flash_attn_f32_f16_aligned`. With both settings, the models finished warm-up but failed during prompt evaluation at `matmul_q4_0_f32_f16acc_aligned_m` (default microbatch) or `matmul_q4_0_f32_f16acc_aligned_s` (`-ub 16`).

On the Galaxy S25 Ultra (SM-S9380, SM8750, firmware `S9380ZCS8BZA1`, Android API 36), the Adreno 830 driver reported Vulkan 1.3.284 and driver version `0x80320001`. Both Vulkan prompts completed with full offload and reached their output limits. The CPU translated the sentence as “GPU可以并行处理许多任务。” and answered “十五”.

On the S25 Ultra, disabling Flash Attention still produced incorrect text on both models. With `-fa off -ub 16`, the translation again returned question marks, and the 1.5B run aborted after the driver logged `Failed to link shaders` and Venus reported an error at `vkCmdBindPipeline`. With `-fa off -ub 1 --no-warmup`, both runs finished with incorrect text. Setting `GGML_VK_DISABLE_INTEGER_DOT_PRODUCT=1`, `GGML_VK_DISABLE_F16=1` or `GGML_VK_DISABLE_FUSION=1` individually also failed to recover either answer.

On the same S25 Ultra firmware, an Android-native build of llama.cpp b9564 used the SPIR-V from Alpine's Vulkan package, the same GGUF files and the same prompts. With full offload directly to Adreno 830, the 0.5B translation produced 64 `@` characters and the 1.5B arithmetic answer began “不信 technicalwij”, as it did in the guest. The native CPU controls translated the sentence correctly and answered “15”. With `-fa off -ub 16`, native 1.5B inference aborted while creating the `mul_mat_vec_q4_0_q8_1_f32` compute pipeline, and the Adreno driver logged `Failed to link shaders`. Both failure modes therefore occur independently of Appine and Venus on this firmware.

The Pixel 11 Pro CPU answered both prompts correctly. Selecting `--device Vulkan0 -ngl 99` explicitly reproduced the translation failure. With `GGML_VK_DISABLE_COOPMAT=1`, the translation timed out after 120 seconds.

### PowerVR correctness

On the stock debug APK and Alpine packages, adding `-fa off -ub 16` to the full-offload command produced “一个GPU可以同时处理许多任务。” at 0.5B and “15” at 1.5B. The logs confirmed 25/25 and 29/29 layers on Vulkan. Both answers repeated with warm-up disabled. A microbatch of one also passed both prompts with warm-up disabled. For the same 47-token translation prompt, changing only the microbatch from 32 to 33 with Flash Attention off changed a correct translation into whitespace. At a microbatch of 16, enabling automatic Flash Attention produced unrelated text. The throughput table below uses the original settings.

An Android-native build of the same llama.cpp revision used the SPIR-V extracted from Alpine’s Vulkan package. The tensor comparisons used explicit fence synchronization to isolate numerical errors. Reading back the 0.5B model’s first layer exposed two problems with the backend’s 128-lane subgroup configuration, independently of Appine and Venus.

| Operation | Native PowerVR observation | Cause and control |
| --- | --- | --- |
| Q4_0 query projection, Flash Attention off | With token IDs starting at 1234, the first-layer query tensor had RMS 0.62405 at 32 tokens (CPU 0.62397). At 33 tokens it was all zeros (CPU 0.62961). | The trace switched from the small to the medium matrix-multiply tile. The medium tile sets `BM=64` and `WM=128`. The shader uses the integer quotient `BM / WM` as a divisor and modulus for subgroup coordinates. Forcing the small tile for the same 33 tokens restored RMS 0.62966. |
| Cooperative-matrix Flash Attention | For token 1234 alone, grouped-query attention selected a 512-thread workgroup, four subgroups and 64 columns. The first four output values were about −3.4 × 10³⁸. The CPU values were −0.01025, −0.01495, −0.02132 and −0.01427. | Each subgroup gets 128 lanes. The shader assigns `64 / (512 / 4) = 0` columns per thread, skipping both the row-maximum and attention-weight loops. Disabling Flash Attention restored the first-layer attention output to RMS 0.02374 (CPU 0.02375). |

With the fence control below and the small matrix tile forced, the native build translated the prompt correctly using either ordinary attention or the scalar Flash Attention shader with 32-lane subgroups. Both runs retained full GPU offload. [Tile selection](https://github.com/ggml-org/llama.cpp/blob/3b3da01dc21dc68e958efb898ab739c65ed08ca2/ggml/src/ggml-vulkan/ggml-vulkan.cpp#L7800) · [Matrix shader](https://github.com/ggml-org/llama.cpp/blob/3b3da01dc21dc68e958efb898ab739c65ed08ca2/ggml/src/ggml-vulkan/vulkan-shaders/mul_mm.comp#L193) · [Attention shader](https://github.com/ggml-org/llama.cpp/blob/3b3da01dc21dc68e958efb898ab739c65ed08ca2/ggml/src/ggml-vulkan/vulkan-shaders/flash_attn_cm1.comp#L349)

A separate native driver check held a compute submission behind a timeline semaphore. In three paired runs, a later `vkQueueSubmit(queue, 0, NULL, fence)` signaled its fence while the work fence was still unsignaled. Submitting one empty `VkSubmitInfo` instead kept the fence pending until the host released the semaphore. All six dispatches then verified 65,536 words. Vulkan requires the fence to cover earlier commands on the same queue. Changing the zero-batch call in native llama.cpp raised the 64 × 5 × 4 × 3 RMSNorm CPU comparisons from 3/11 to 11/11 in one paired run. Applying the same substitution to the renderer’s fence submissions alone still produced incorrect text. [Vulkan fence signal scope](https://docs.vulkan.org/spec/latest/chapters/synchronization.html#synchronization-fences-signaling)

### Throughput

All four phones used a debug APK, a Tier 1 Alpine 3.24.3 guest and UID 1000. Each numeric cell shows the two pass means in tokens per second. `llama-bench -t 4 -p 128 -n 32 -r 3` ran 0.5B CPU, 1.5B Vulkan, 1.5B CPU and 0.5B Vulkan, then repeated the sequence in reverse. CPU used `-dev none -ngl 0` and Vulkan used `-dev Vulkan0 -ngl 99`. The Pixel 11 Pro and Galaxy S25 Ultra both failed the default Vulkan text checks. `llama-bench` measures token throughput without checking the answers.

| Device | Model | Prompt, CPU | Prompt, Vulkan | Generation, CPU | Generation, Vulkan |
| --- | --- | ---: | ---: | ---: | ---: |
| Pixel 11 Pro | 0.5B | 341.32 / 441.35 | 180.92 / 179.38 | 70.73 / 94.60 | 6.97 / 6.64 |
| Pixel 8 | 0.5B | 320.55 / 298.86 | 44.63 / 44.68 | 68.28 / 63.63 | 27.14 / 26.30 |
| Galaxy S23 | 0.5B | 195.33 / 156.39 | Failed | 55.84 / 48.73 | Failed |
| Galaxy S25 Ultra | 0.5B | 456.98 / 439.79 | 68.88 / 69.23 | 134.21 / 128.10 | 70.31 / 68.87 |
| Pixel 11 Pro | 1.5B | 75.75 / 67.87 | 71.93 / 72.58 | 27.23 / 20.65 | 3.64 / 3.63 |
| Pixel 8 | 1.5B | 100.69 / 90.57 | 12.63 / 12.57 | 22.54 / 20.30 | 11.94 / 11.94 |
| Galaxy S23 | 1.5B | 67.81 / 59.98 | Failed | 18.19 / 18.60 | Failed |
| Galaxy S25 Ultra | 1.5B | 140.93 / 142.14 | 22.56 / 20.13 | 37.91 / 39.32 | 39.00 / 33.43 |

Both Galaxy phones used the same debug APK under a separate application ID and restarted the guest for each benchmark invocation. On the S23, both Vulkan passes for each model were stopped after the same pipeline error, before `llama-bench` reported a rate. During the two passes, the battery temperature ranged from 36.9 to 38.3 °C and all 11 thermal-status samples were 0.

Across the two pass means, the S25 Ultra CPU generated tokens 2.51× as fast as the S23 at 0.5B and 2.10× as fast at 1.5B. On the S25 Ultra, the battery temperature rose from 31.9 to 35.4 °C during the benchmark. Android thermal status rose from 0 to 2 across 12 samples.

At 1.5B, Vulkan prompt throughput was within 1% of CPU on the Pixel 11 Pro. On the Pixel 8, the CPU processed prompts 7.59× as fast as Vulkan. For generation, the CPU lead narrowed from 12.15× at 0.5B to 6.59× at 1.5B on the Pixel 11 Pro and from 2.47× to 1.79× on the Pixel 8. Both phones reported thermal status 0 throughout sampling. Battery temperatures were 27.5–30.2 °C on the Pixel 11 Pro and 32.9–34.5 °C on the Pixel 8.

### Packages and model files

All four phones used Alpine's `llama.cpp` and `llama.cpp-vulkan` 0.0.9564-r0 with `mesa-vulkan-virtio` 26.1.6-r0. To run the translation check with the GGUF in the current directory:

```sh
doas apk add llama.cpp llama.cpp-vulkan mesa-vulkan-virtio
llama-cli --list-devices
llama-cli -m ./qwen2.5-0.5b-instruct-q4_0.gguf -t 4 -c 512 -n 64 --temp 0 -st \
    -p '翻译成中文，只输出译文：A GPU can process many tasks in parallel.'
```

| Model | GGUF SHA-256 |
| --- | --- |
| 0.5B | `7671c0c304e6ce5a7fc577bcb12aba01e2c155cc2efd29b2213c95b18edaf6ed` |
| 1.5B | `dcd819ff094852c38faba6873d8ff0c9d51eadb2844539e52042ae5d647bbfdb` |

## Reproduce

Build the Android app using the [Android build guide](../android/README.md#building). The disposable fixture builder uses ARM64 Docker images and the pinned DRM headers for the low-level lifetime test. The Vulkan sample links the selected distribution's own loader. From the repository root with a debug build installed on the selected device:

```sh
scripts/fetch-virglrenderer
android/gradlew -p android installDebug installDebugAndroidTest
mkdir -p target/gpu-survey
for distro in alpine debian; do
    tests/survey/gpu/fixture "$distro" "target/gpu-survey/venus-$distro.tgz"
    adb push "target/gpu-survey/venus-$distro.tgz" "/data/local/tmp/venus-$distro.tgz"
    adb shell run-as io.github.mthli.appine mkdir -p cache
    adb shell run-as io.github.mthli.appine cp "/data/local/tmp/venus-$distro.tgz" cache/
    adb shell am instrument --user 0 -w -r -e gpuDistro "$distro" \
        -e class io.github.mthli.appine.GpuTest#distributionVenus \
        io.github.mthli.appine.test/androidx.test.runner.AndroidJUnitRunner
done
adb logcat -d -s appine-gpu-test:I
```

For the native driver probe, set `ANDROID_HOME` to the Android SDK directory. Each invocation reports the device, extensions, first failing operation or verified word count.

```sh
android/gradlew -p tests/survey/gpu/android assembleDebug
adb install -r --user 0 tests/survey/gpu/android/build/outputs/apk/debug/gpu-probe-debug.apk
for path in dma-buf opaque-fd dedicated-control android-blob cpu-export-blob; do
    adb shell am instrument --user 0 -w -r -e path "$path" io.github.mthli.appine.gpuprobe/.Probe
done
```
