{
    "targets": [{
        "target_name": "openabejs",
        "cflags!": [ "-fno-exceptions" ],
        "cflags_cc!": [ "-fno-exceptions",'-fno-rtti' ],
        "cflags": [ "-fexceptions" ],
        "cflags_cc": [ "-fexceptions", "-pthread", "-Wall", "-g", "-O2", "-DSSL_LIB_INIT" ],

        "sources": [
            "cppsrc/main.cpp",
            "cppsrc/openabejs/openabejs.cc",

        ],
        'include_dirs': [
            "<!@(node -p \"require('node-addon-api').include\")",
            "./cppsrc/openabe/deps/root/include",
            "./cppsrc/openabe/root/include",

        ],
        'link_settings':{
          'ldflags': [],
          },
        'libraries': ['-lcrypto', '-lrelic', '-lrelic_ec', '-lopenabe'],
        'dependencies': [
            "<!(node -p \"require('node-addon-api').gyp\")"
        ],
        'defines': ['NAPI_DISABLE_CPP_EXCEPTIONS']
    }]
}
