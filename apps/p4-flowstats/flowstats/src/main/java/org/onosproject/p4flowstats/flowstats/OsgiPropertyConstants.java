/*
 * Copyright 2018-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.onosproject.p4flowstats.flowstats;

public final class OsgiPropertyConstants {
    
    private OsgiPropertyConstants() {
    }

    // Flow Rule parameters for the FlowStats app.

    static final String FLOW_RULE_CM_SKETCH = "flowRuleCmSketch";
    static final boolean FLOW_RULE_CM_SKETCH_DEFAULT = true;

    static final String FLOW_RULE_BM_SKETCH = "flowRuleBmSketch";
    static final boolean FLOW_RULE_BM_SKETCH_DEFAULT = true;

    static final String FLOW_RULE_AMS_SKETCH = "flowRuleAmsSketch";
    static final boolean FLOW_RULE_AMS_SKETCH_DEFAULT = true;

    static final String FLOW_RULE_MV_SKETCH = "flowRuleMvSketch";
    static final boolean FLOW_RULE_MV_SKETCH_DEFAULT = true;            
}
