/* Build with:
 * zig cc -target x86_64-windows-gnu -O2 -shared -nostdlib \
 *   -fno-sanitize=all -Wl,--entry,DllMain factory.c -o winrt.pe
 * Add -DFACTORY_NAME=OrdinaryApi for reference-only.pe.
 */
#ifndef FACTORY_NAME
#define FACTORY_NAME DllGetActivationFactory
#endif

__declspec(dllexport) const char *factory_reference = "DllGetActivationFactory";

__declspec(dllexport) long FACTORY_NAME(void *name, void **factory) {
    *factory = 0;
    return (long)0x80040111;
}

int DllMain(void *module, unsigned long reason, void *reserved) {
    return 1;
}
