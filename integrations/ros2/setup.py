"""ament_python build for the vouch_ros2 package."""

import os
from glob import glob

from setuptools import find_packages, setup

package_name = "vouch_ros2"

setup(
    name=package_name,
    version="2.1.0",
    packages=find_packages(exclude=["test", "test.*"]),
    data_files=[
        # ament resource index marker: how ROS 2 discovers the package.
        ("share/ament_index/resource_index/packages", ["resource/" + package_name]),
        (os.path.join("share", package_name), ["package.xml", "README.md"]),
        (os.path.join("share", package_name, "launch"), glob("launch/*.launch.py")),
        (os.path.join("share", package_name, "config"), glob("config/*.yaml")),
    ],
    install_requires=["setuptools", "vouch-protocol>=2.1.0"],
    zip_safe=True,
    maintainer="Vouch Protocol Contributors",
    maintainer_email="hello@vouch-protocol.com",
    description=(
        "Vouch accountability gate for ROS 2: model provenance on startup, a "
        "pre-actuation physical capability scope gate, and a tamper-evident black box."
    ),
    license="Apache-2.0",
    tests_require=["pytest"],
    entry_points={
        "console_scripts": [
            "vouch_action_gate = vouch_ros2.node:main",
        ],
    },
)
