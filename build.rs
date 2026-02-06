fn main() {
    // ESP-IDF embuild setup
    // The partition table is handled by the lunarcore_config component
    // via components/lunarcore_config/CMakeLists.txt
    embuild::espidf::sysenv::output();
}
