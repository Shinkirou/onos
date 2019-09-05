COMPILE_DEPS = CORE_DEPS + [
    "@minimal_json//jar",
    "//protocols/p4runtime/model:onos-protocols-p4runtime-model",
    "//protocols/p4runtime/api:onos-protocols-p4runtime-api",
    "//drivers/default:onos-drivers-default",
    '//apps/p4-sketches/pipeconf:onos-apps-p4-sketches-pipeconf',
]

osgi_jar(
    deps = COMPILE_DEPS,
)

BUNDLES = [
    "//apps/p4-univmon/univmon:onos-apps-p4-univmon-univmon",
]

onos_app(
    app_name = "org.onosproject.p4univmon.univmon",
    category = "Pipeconf",
    description = "Provides pipeconf for the ONOS-P4 Tutorial",
    included_bundles = BUNDLES,
    required_apps = [
        "org.onosproject.drivers.p4runtime",
    ],
    title = "P4 Univmon",
    url = "http://onosproject.org",
)
