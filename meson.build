project('Long-decompiler', 'cpp',
    default_options: ['cpp_std=c++17'])

include_dir = include_directories('include')

# programs used
yacc = find_program('bison')
lex = find_program('flex')
doxygen = find_program('doxygen', required : false)

# external libraries
compiler = meson.get_compiler('cpp')
libbfd = compiler.find_library('libbfd', required : false)

yacc_generator = generator(
    yacc,
    output : ['@BASENAME@.cpp', '@BASENAME@.hpp'],
    arguments : ['-d', '-o', '@OUTPUT0@', '@INPUT@']
)

lex_generator = generator(
    lex,
    output : ['@BASENAME@.cpp'],
    arguments : ['-o', '@OUTPUT@', '@INPUT@']
)

# generate needed source files
gen_grammar = yacc_generator.process('src/grammar.y')
gen_xml = yacc_generator.process('src/xml.y')
gen_pcodeparse = yacc_generator.process('src/pcodeparse.y')
gen_slghparse = yacc_generator.process('src/slghparse.y')
gen_slghscan = lex_generator.process('src/slghscan.l')
gen_ruleparse = yacc_generator.process('src/ruleparse.y')

core_sources = [
    'src/space.cc',
    'src/float.cc',
    'src/address.cc',
    'src/pcoderaw.cc',
    'src/translate.cc',
    'src/opcodes.cc',
    'src/globalcontext.cc',

    # generated
    gen_xml,
]

decompiler_core_sources = [
    'src/capability.cc',
    'src/architecture.cc',
    'src/options.cc',
    'src/graph.cc',
    'src/cover.cc',
    'src/block.cc',
    'src/cast.cc',
    'src/typeop.cc',
    'src/database.cc',
    'src/cpool.cc',
    'src/comment.cc',
    'src/fspec.cc',
    'src/action.cc',
    'src/loadimage.cc',
    'src/varnode.cc',
    'src/op.cc',
    'src/type.cc',
    'src/variable.cc',
    'src/varmap.cc',
    'src/jumptable.cc',
    'src/emulate.cc',
    'src/emulateutil.cc',
    'src/flow.cc',
    'src/userop.cc',
    'src/funcdata.cc',
    'src/funcdata_block.cc',
    'src/funcdata_op.cc',
    'src/funcdata_varnode.cc',
    'src/pcodeinject.cc',
    'src/heritage.cc',
    'src/prefersplit.cc',
    'src/rangeutil.cc',
    'src/ruleaction.cc',
    'src/subflow.cc',
    'src/blockaction.cc',
    'src/merge.cc',
    'src/double.cc',
    'src/coreaction.cc',
    'src/condexe.cc',
    'src/override.cc',
    'src/dynamic.cc',
    'src/crc32.cc',
    'src/prettyprint.cc',
    'src/printlanguage.cc',
    'src/printc.cc',
    'src/printjava.cc',
    'src/memstate.cc',
    'src/opbehavior.cc',
    'src/paramid.cc',

    # generated
    # gen_grammar,

    # TODO external core extension sources
]

sleigh_sources = [
    'src/sleigh.cc',
    'src/pcodecompile.cc',
    'src/sleighbase.cc',
    'src/slghsymbol.cc',
    'src/slghpatexpress.cc',
    'src/slghpattern.cc',
    'src/semantics.cc',
    'src/context.cc',
    'src/filemanage.cc',
    
    # generated
    gen_pcodeparse,
]

ghidra_sources = [
    'src/ghidra_arch.cc',
    'src/inject_ghidra.cc',
    'src/ghidra_translate.cc',
    'src/loadimage_ghidra.cc',
    'src/typegrp_ghidra.cc',
    'src/database_ghidra.cc',
    'src/ghidra_context.cc',
    'src/cpool_ghidra.cc',
    'src/ghidra_process.cc',
    'src/comment_ghidra.cc',
    # TODO ghidra extension sources
]

sla_compiler_sources = [
    'src/slgh_compile.cc',

    # generated
    #'src/gen/slghparse.cc',
    #'src/gen/slghscan.cc',
    gen_slghparse,
    gen_slghscan,
]

special_sources = [
    'src/consolemain.cc',
    'src/sleighexample.cc'
]

extra_sources = [
    'src/ifacedecomp.cc',
    'src/ifaceterm.cc',
    'src/interface.cc',
    'src/interface.cc',
]

if get_option('arch') != 'x86_64'
    if build_machine.system() != 'linux'
        error('set arch to 32-bit is only available under linux')
    endif
endif

system = build_machine.system()
arch_type = ''
additional_flags = []
if system == 'linux'
    if get_option('arch') == 'x86'
        arch_type = '-m32'
    elif get_option('arch') == 'x86_64'
        arch_type = '-m64'
    endif
elif system == 'darwin'
    arch_type = ['-arch', 'x86_64']
    additional_flags = ['-std=c++17', '-mmacosx-version-min=10.6', '-w']
endif

commandline_debug_def = ['-DCPUI_DEBUG', '-D__TERMINAL__']
commandline_opt_def = '-D__TERMINAL__'

ghidra_debug_def = '-DCPUI_DEBUG'

sleigh_debug_def = '-DYYDEBUG'

debug_cxx_flags = ''
if get_option('debug')
    debug_cxx_flags = ['-g', '-Wall', '-Wno-sign-compare']
endif

if doxygen.found()
    custom_target('doc', command : [doxygen, 'src/Doxyfile'], 
        input : 'Doxyfile',
        output : 'html')
endif

commandline_target_sources = core_sources + \
    decompiler_core_sources + \
    extra_sources + \
    sleigh_sources + ['src/consolemain.cc']
executable(
    'commandline-decompiler', 
    dependencies : [libbfd],
    include_directories : include_dir,
    sources: commandline_target_sources,
    cpp_args : [debug_cxx_flags, arch_type, additional_flags])

ghidra_target_sources = core_sources + \
    decompiler_core_sources + \
    ghidra_sources
executable(
    'ghidra-decompiler',
    include_directories : include_dir,
    sources: ghidra_target_sources,
    cpp_args: [debug_cxx_flags, arch_type, additional_flags])

# TODO sleigh targets
