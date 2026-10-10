"""
Cython build configuration for omnibioai-policy-engine IP protection.
Usage: python setup.py build_ext --inplace
"""
import os

from Cython.Build import cythonize
from Cython.Compiler import Options
from setuptools import find_packages, setup
from setuptools.extension import Extension

Options.annotate = False

EXTENSIONS = [
    "app/core/engine.py",
    "app/core/rbac.py",
    "app/core/abac.py",
    "app/core/rules.py",
    "app/core/permissions.py",
    "app/core/tenancy.py",
    "app/services/policy_service.py",
    "app/services/cache.py",
    "app/api/routes_policy.py",
]


def make_extensions(paths):
    exts = []
    for p in paths:
        if not os.path.exists(p):
            print(f"WARNING: {p} not found, skipping")
            continue
        module = p.replace("/", ".").replace("\\", ".").removesuffix(".py")
        exts.append(Extension(module, [p]))
    return exts


setup(
    name="omnibioai-policy-engine",
    packages=find_packages(exclude=["tests*", "migrations*"]),
    ext_modules=cythonize(
        make_extensions(EXTENSIONS),
        compiler_directives={
            "language_level": "3",
            "boundscheck": False,
            "wraparound": False,
            "cdivision": True,
        },
        # Default to serial generation: cythonize's multiprocessing pool uses
        # "spawn" on macOS, which re-imports this module in each worker and
        # crashes (BrokenProcessPool) before any extension is built. Opt into
        # parallel generation explicitly (e.g. in Linux CI) via this env var.
        nthreads=int(os.environ.get("CYTHON_NTHREADS", "0")),
    ),
    zip_safe=False,
)
