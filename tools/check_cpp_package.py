"""Build and install MAML profiles, then consume only their exported CMake targets."""
import argparse
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]


def run(*args):
    subprocess.run([str(a) for a in args], check=True)


def check(source, root, enabled):
    profile = 'decoder' if enabled else 'core'
    build, prefix, consumer = (root / profile / name for name in ('build', 'prefix', 'consumer'))
    consumer.mkdir(parents=True)
    run('cmake', '-S', source, '-B', build, '-DCMAKE_BUILD_TYPE=Release',
        '-DMAML_BUILD_TESTS=OFF', '-DMAML_BUILD_TOOLS=OFF',
        '-DCMAKE_C_STANDARD=11', '-DCMAKE_C_EXTENSIONS=OFF',
        '-DMAML_ENABLE_INSN=' + ('ON' if enabled else 'OFF'),
        '-DCMAKE_INSTALL_PREFIX=' + str(prefix))
    run('cmake', '--build', build, '--config', 'Release', '--parallel', '2')
    run('cmake', '--install', build, '--config', 'Release')
    component = ' COMPONENTS insn' if enabled else ''
    (consumer / 'CMakeLists.txt').write_text(f'''cmake_minimum_required(VERSION 3.19)
project(consumer LANGUAGES CXX)
find_package(maml CONFIG REQUIRED{component} PATHS "{prefix.as_posix()}" NO_DEFAULT_PATH)
add_executable(consumer main.cpp)
target_link_libraries(consumer PRIVATE maml::maml)
''')
    (consumer / 'main.cpp').write_text('''#include <maml.hpp>
#include <array>
int main() {
    std::array<unsigned char,4> bytes{0x8B,0x41,0xF8,0xC3};
    maml::v1::Image image{bytes};
    if(maml::v1::Pattern("8B 41 ??").find_all(image).size()!=1) return 1;
#if MAML_ENABLE_INSN
    std::array<maml::generate::Function,1> functions{{{0,{{0,4}}}}};
    std::array<maml::generate::Range,2> instructions{{{0,3},{3,4}}};
    auto result=maml::v1::Pipeline("bytes(\\"C3\\") -> insn(\\"read disp(d)\\") -> capture(\\"d\\") -> unique")
        .run(image,{},{},functions,instructions);
    return result.values.at(0).as_signed()==-8 ? 0 : 2;
#else
    try { maml::v1::Pipeline p("bytes(\\"C3\\") -> insn(\\"read disp(d)\\")"); }
    catch(const maml::v1::Error& e) { return e.code=="UnsupportedFeature" ? 0 : 3; }
    return 4;
#endif
}
''')
    out = consumer / 'build'
    run('cmake', '-S', consumer, '-B', out, '-DCMAKE_BUILD_TYPE=Release')
    run('cmake', '--build', out, '--config', 'Release')
    binary = out / 'consumer'
    if not binary.exists():
        binary = out / 'Release' / 'consumer.exe'
    run(binary)
    print(profile + ': installed CMake consumer passed', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='maml-consumer-') as directory:
        for enabled in (False, True):
            check(args.source.resolve(), Path(directory), enabled)


if __name__ == '__main__':
    main()
