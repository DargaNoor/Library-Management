private static String manualGetJsonValue(String json, String key) {
    int startIndex = json.indexOf("\"" + key + "\"");
    if (startIndex == -1) return null;
    startIndex = json.indexOf(":", startIndex) + 1;
    while (startIndex < json.length() && json.charAt(startIndex) == ' ') startIndex++;
    if (startIndex >= json.length()) return null;
    int endIndex = startIndex;
    if (json.charAt(startIndex) == '"') {
        startIndex++;
        endIndex = json.indexOf("\"", startIndex);
    } else {
        endIndex = json.indexOf(",", startIndex);
        if (endIndex == -1) endIndex = json.indexOf("}", startIndex);
    }
    if (endIndex == -1) endIndex = json.length();
    return json.substring(startIndex, endIndex);
}







public class Main {
    public static void main(String[] args) {
        // Example string representing the data array in JSON format
        String dataString = "[{\"seqNo\":\"SEQN0001\",\"DataType\":\"UID\",\"Data\":\"507339736890\",\"DataHashFormat\":\"U\"},{\"seqNo\":\"SEQN0002\",\"DataType\":\"RefKey\",\"Data\":\"2819pVxvXhII\",\"DataHashFormat\":\"I\"}]";

        // Manually parse the JSON array
        dataString = dataString.trim();
        if (dataString.startsWith("[") && dataString.endsWith("]")) {
            dataString = dataString.substring(1, dataString.length() - 1);
            String[] elements = splitJsonArray(dataString);
            for (String element : elements) {
                String dataValue = manualGetJsonValue(element, "Data");
                if (dataValue != null) {
                    String maskedData = maskData(dataValue);
                    System.out.println("Data tag name with masked value: " + maskedData);
                }
            }
        }
    }

    private static String[] splitJsonArray(String jsonArray) {
        // Simple manual splitter for JSON array elements
        jsonArray = jsonArray.trim();
        if (jsonArray.isEmpty()) {
            return new String[0];
        }
        String[] elements = jsonArray.split("\\},\\{");
        for (int i = 0; i < elements.length; i++) {
            if (!elements[i].startsWith("{")) {
                elements[i] = "{" + elements[i];
            }
            if (!elements[i].endsWith("}")) {
                elements[i] = elements[i] + "}";
            }
        }
        return elements;
    }

    private static String manualGetJsonValue(String json, String key) {
        // Manual JSON value extractor
        int index = json.indexOf("\"" + key + "\":\"");
        if (index == -1) {
            return null;                 
        }
        index += key.length() + 3;                             
        int endIndex = json.indexOf("// Key not found
        }
        index += key.length() + 3; // Move past the key and ":"
        int endIndex = json.indexOf("\"", index);
        if (endIndex == -1) {
            return null; // End quote not found
        }
        return json.substring(index, endIndex);
    }

    private static String maskData(String data) {
        if (data.length() > 9) {
            return "*********" + data.substring(9);
        } else if (data.length() == 9) {
            return "*********";
        } else {
            // For data shorter than 9 characters, mask all
            return "*".repeat(data.length());
        }
    }
}









lllllllllllll










public class Main {
    public static void main(String[] args) {
        String jsonString = "{\"purseInfoList\":{\"purseInfo\":[{\"purseId\":\"TRAVEL\",\"purseCurrency\":\"AED\",\"purseAvailableBalance\":\"0.00\",\"purseCurrentBalance\":\"0.00\",\"purseStatus\":\"A\"},{\"purseId\":\"TRAVEL\",\"purseCurrency\":\"CAD\",\"purseAvailableBalance\":\"0.00\",\"purseCurrentBalance\":\"0.00\",\"purseStatus\":\"A\"},{\"purseId\":\"TRAVEL\",\"purseCurrency\":\"AUD\",\"purseAvailableBalance\":\"0.00\",\"purseCurrentBalance\":\"0.00\",\"purseStatus\":\"A\"},{\"purseId\":\"TRAVEL\",\"purseCurrency\":\"EUR\",\"purseAvailableBalance\":\"0.00\",\"purseCurrentBalance\":\"0.00\",\"purseStatus\":\"A\"},{\"purseId\":\"TRAVEL\",\"purseCurrency\":\"USD\",\"purseAvailableBalance\":\"0.00\",\"purseCurrentBalance\":\"0.00\",\"purseStatus\":\"A\"},{\"purseId\":\"TRAVEL\",\"purseCurrency\":\"GBP\",\"purseAvailableBalance\":\"0.00\",\"purseCurrentBalance\":\"0.00\",\"purseStatus\":\"A\"},{\"purseId\":\"TRAVEL\",\"purseCurrency\":\"SGD\",\"purseAvailableBalance\":\"0.00\",\"purseCurrentBalance\":\"0.00\",\"purseStatus\":\"A\"}]}}";

        // Manually extract the "purseInfo" array block
        String purseInfoArrayRaw = extractArray(jsonString, "\"purseInfo\":[");

        // Split individual JSON objects
        String[] purseInfos = splitJsonArray(purseInfoArrayRaw);

        // Prepare value arrays
        String[] purseId = new String[purseInfos.length];
        String[] purseCurrency = new String[purseInfos.length];
        String[] purseAvailableBalance = new String[purseInfos.length];
        String[] purseCurrentBalance = new String[purseInfos.length];
        String[] purseStatus = new String[purseInfos.length];

        // Fill arrays from each object
        for (int i = 0; i < purseInfos.length; i++) {
            purseId[i] = getJsonValue(purseInfos[i], "purseId");
            purseCurrency[i] = getJsonValue(purseInfos[i], "purseCurrency");
            purseAvailableBalance[i] = getJsonValue(purseInfos[i], "purseAvailableBalance");
            purseCurrentBalance[i] = getJsonValue(purseInfos[i], "purseCurrentBalance");
            purseStatus[i] = getJsonValue(purseInfos[i], "purseStatus");
        }

        // Construct final JSON string
        String expectedOutput = "{\"purseInfoList\":{\"purseInfo\":{"
                + "\"purseId\":[\"" + String.join("\",\"", purseId) + "\"],"
                + "\"purseCurrency\":[\"" + String.join("\",\"", purseCurrency) + "\"],"
                + "\"purseAvailableBalance\":[\"" + String.join("\",\"", purseAvailableBalance) + "\"],"
                + "\"purseCurrentBalance\":[\"" + String.join("\",\"", purseCurrentBalance) + "\"],"
                + "\"purseStatus\":[\"" + String.join("\",\"", purseStatus) + "\"]"
                + "}}}";

        System.out.println(expectedOutput);
    }

    // Extract content of JSON array starting from a given key
    public static String extractArray(String json, String arrayKey) {
        int start = json.indexOf(arrayKey) + arrayKey.length();
        int end = start;
        int open = 1;

        while (end < json.length() && open > 0) {
            char c = json.charAt(end++);
            if (c == '[') open++;
            else if (c == ']') open--;
        }

        return json.substring(start, end - 1).trim();
    }

    // Split JSON objects within array
    public static String[] splitJsonArray(String arrayBody) {
        List<String> objects = new ArrayList<>();
        int start = 0;
        int braces = 0;
        for (int i = 0; i < arrayBody.length(); i++) {
            char c = arrayBody.charAt(i);
            if (c == '{') {
                if (braces == 0) start = i;
                braces++;
            } else if (c == '}') {
                braces--;
                if (braces == 0) {
                    objects.add(arrayBody.substring(start, i + 1));
                }
            }
        }
        return objects.toArray(new String[0]);
    }

    // Extract simple key-value from flat JSON object
    public static String getJsonValue(String json, String key) {
        String search = "\"" + key + "\":";
        int index = json.indexOf(search);
        if (index == -1) return "";

        index += search.length();
        while (index < json.length() && (json.charAt(index) == ' ' || json.charAt(index) == '\"')) index++;

        int end = index;
        while (end < json.length() && json.charAt(end) != '\"' && json.charAt(end) != ',' && json.charAt(end) != '}') end++;

        return json.substring(index, end).replaceAll("\"", "").trim();
    }
}








........













public class Main {
    public static void main(String[] args) {
        String jsonString = "{\"purseInfoList\":{\"purseInfo\":[{\"purseId\":\"TRAVEL\",\"purseCurrency\":\"AED\",\"purseAvailableBalance\":\"0.00\",\"purseCurrentBalance\":\"0.00\",\"purseStatus\":\"A\"},{\"purseId\":\"TRAVEL\",\"purseCurrency\":\"CAD\",\"purseAvailableBalance\":\"0.00\",\"purseCurrentBalance\":\"0.00\",\"purseStatus\":\"A\"},{\"purseId\":\"TRAVEL\",\"purseCurrency\":\"AUD\",\"purseAvailableBalance\":\"0.00\",\"purseCurrentBalance\":\"0.00\",\"purseStatus\":\"A\"},{\"purseId\":\"TRAVEL\",\"purseCurrency\":\"EUR\",\"purseAvailableBalance\":\"0.00\",\"purseCurrentBalance\":\"0.00\",\"purseStatus\":\"A\"},{\"purseId\":\"TRAVEL\",\"purseCurrency\":\"USD\",\"purseAvailableBalance\":\"0.00\",\"purseCurrentBalance\":\"0.00\",\"purseStatus\":\"A\"},{\"purseId\":\"TRAVEL\",\"purseCurrency\":\"GBP\",\"purseAvailableBalance\":\"0.00\",\"purseCurrentBalance\":\"0.00\",\"purseStatus\":\"A\"},{\"purseId\":\"TRAVEL\",\"purseCurrency\":\"SGD\",\"purseAvailableBalance\":\"0.00\",\"purseCurrentBalance\":\"0.00\",\"purseStatus\":\"A\"}]}}";

        // Manually parse the JSON string
        String purseInfoListJson = getJsonValue(jsonString, "purseInfoList");
        String purseInfoJsonArray = getJsonValue(purseInfoListJson, "purseInfo");

        // Extract the purseInfo array
        String[] purseInfoArray = splitJsonArray(purseInfoJsonArray);

        // Initialize the output arrays
        String[] purseId = new String[purseInfoArray.length];
        String[] purseCurrency = new String[purseInfoArray.length];
        String[] purseAvailableBalance = new String[purseInfoArray.length];
        String[] purseCurrentBalance = new String[purseInfoArray.length];
        String[] purseStatus = new String[purseInfoArray.length];

        // Populate the output arrays
        for (int i = 0; i < purseInfoArray.length; i++) {
            purseId[i] = getJsonValue(purseInfoArray[i], "purseId");
            purseCurrency[i] = getJsonValue(purseInfoArray[i], "purseCurrency");
            purseAvailableBalance[i] = getJsonValue(purseInfoArray[i], "purseAvailableBalance");
            purseCurrentBalance[i] = getJsonValue(purseInfoArray[i], "purseCurrentBalance");
            purseStatus[i] = getJsonValue(purseInfoArray[i], "purseStatus");
        }

        // Construct the expected output JSON string
        String expectedOutput = "{\"purseInfoList\":{\"purseInfo\":{\"purseId\":[\"" + String.join("\",\"", purseId) + "\"],\"purseCurrency\":[\"" + String.join("\",\"", purseCurrency) + "\"],\"purseAvailableBalance\":[\"" + String.join("\",\"", purseAvailableBalance) + "\"],\"purseCurrentBalance\":[\"" + String.join("\",\"", purseCurrentBalance) + "\"],\"purseStatus\":[\"" + String.join("\",\"", purseStatus) + "\"]}}}";

        System.out.println(expectedOutput);
    }

    // Helper method to get a JSON value
    public static String getJsonValue(String json, String key) {
        int startIndex = json.indexOf("\"" + key + "\":");
        if (startIndex == -1) return null;
        startIndex += key.length() + 2;
        int endIndex = json.indexOf(",", startIndex);
        if (endIndex == -1) endIndex = json.indexOf("}", startIndex);
        if (endIndex == -1) endIndex = json.length();
        String value = json.substring(startIndex, endIndex).trim();
        if (value.startsWith("\"")) value = value.substring(1, value.length() - 1);
        return value;
    }

                                          
    public static String[] splitJsonArray(String jsonArray) {
        jsonArray = jsonArray.substring(1, jsonArray.length() - 1);                   
        String[] elements = jsonArray.split("// Helper method to split a JSON array
    public static String[] splitJsonArray(String jsonArray) {
        jsonArray = jsonArray.substring(1, jsonArray.length() - 1); // Remove outer []
        String[] elements = jsonArray.split("\\},\\{");
        for (int i = 0; i < elements.length; i++) {
            if (i == 0 && !elements[i].startsWith("{")) elements[i] = "{" + elements[i];
            if (i == elements.length - 1 && !elements[i].endsWith("public class Main {
    public static void main(String[] args) {
        String jsonString = "{\"purseInfoList\":{\"purseInfo\":[{\"purseId\":\"TRAVEL\",\"purseCurrency\":\"AED\",\"purseAvailableBalance\":\"0.00\",\"purseCurrentBalance\":\"0.00\",\"purseStatus\":\"A\"},{\"purseId\":\"TRAVEL\",\"purseCurrency\":\"CAD\",\"purseAvailableBalance\":\"0.00\",\"purseCurrentBalance\":\"0.00\",\"purseStatus\":\"A\"},{\"purseId\":\"TRAVEL\",\"purseCurrency\":\"AUD\",\"purseAvailableBalance\":\"0.00\",\"purseCurrentBalance\":\"0.00\",\"purseStatus\":\"A\"},{\"purseId\":\"TRAVEL\",\"purseCurrency\":\"EUR\",\"purseAvailableBalance\":\"0.00\",\"purseCurrentBalance\":\"0.00\",\"purseStatus\":\"A\"},{\"purseId\":\"TRAVEL\",\"purseCurrency\":\"USD\",\"purseAvailableBalance\":\"0.00\",\"purseCurrentBalance\":\"0.00\",\"purseStatus\":\"A\"},{\"purseId\":\"TRAVEL\",\"purseCurrency\":\"GBP\",\"purseAvailableBalance\":\"0.00\",\"purseCurrentBalance\":\"0.00\",\"purseStatus\":\"A\"},{\"purseId\":\"TRAVEL\",\"purseCurrency\":\"SGD\",\"purseAvailableBalance\":\"0.00\",\"purseCurrentBalance\":\"0.00\",\"purseStatus\":\"A\"}]}}";

        // Manually parse the JSON string
        String purseInfoListJson = getJsonValue(jsonString, "purseInfoList");
        String purseInfoJsonArray = getJsonValue(purseInfoListJson, "purseInfo");

        // Extract the purseInfo array
        String[] purseInfoArray = splitJsonArray(purseInfoJsonArray);

        // Initialize the output arrays
        String[] purseId = new String[purseInfoArray.length];
        String[] purseCurrency = new String[purseInfoArray.length];
        String[] purseAvailableBalance = new String[purseInfoArray.length];
        String[] purseCurrentBalance = new String[purseInfoArray.length];
        String[] purseStatus = new String[purseInfoArray.length];

        // Populate the output arrays
        for (int i = 0; i < purseInfoArray.length; i++) {
            purseId[i] = getJsonValue(purseInfoArray[i], "purseId");
            purseCurrency[i] = getJsonValue(purseInfoArray[i], "purseCurrency");
            purseAvailableBalance[i] = getJsonValue(purseInfoArray[i], "purseAvailableBalance");
            purseCurrentBalance[i] = getJsonValue(purseInfoArray[i], "purseCurrentBalance");
            purseStatus[i] = getJsonValue(purseInfoArray[i], "purseStatus");
        }

        // Construct the expected output JSON string
        String expectedOutput = "{\"purseInfoList\":{\"purseInfo\":{\"purseId\":[\"" + String.join("\",\"", purseId) + "\"],\"purseCurrency\":[\"" + String.join("\",\"", purseCurrency) + "\"],\"purseAvailableBalance\":[\"" + String.join("\",\"", purseAvailableBalance) + "\"],\"purseCurrentBalance\":[\"" + String.join("\",\"", purseCurrentBalance) + "\"],\"purseStatus\":[\"" + String.join("\",\"", purseStatus) + "\"]}}}";

        System.out.println(expectedOutput);
    }

    // Helper method to get a JSON value
    public static String getJsonValue(String json, String key) {
        int startIndex = json.indexOf("\"" + key + "\":");
        if (startIndex == -1) return null;
        startIndex += key.length() + 2;
        int endIndex = json.indexOf(",", startIndex);
        if (endIndex == -1) endIndex = json.indexOf("}", startIndex);
        if (endIndex == -1) endIndex = json.length();
        String value = json.substring(startIndex, endIndex).trim();
        if (value.startsWith("\"")) value = value.substring(1, value.length() - 1);
        return value;
    }

                                          
    public static String[] splitJsonArray(String jsonArray) {
        jsonArray = jsonArray.substring(1, jsonArray.length() - 1);                   
        String[] elements = jsonArray.split("// Helper method to split a JSON array
    public static String[] splitJsonArray(String jsonArray) {
        jsonArray = jsonArray.substring(1, jsonArray.length() - 1); // Remove outer []
        String[] elements = jsonArray.split("\\},\\{");
        for (int i = 0; i < elements.length; i++) {
            if (i == 0 && !elements[i].startsWith("{")) elements[i] = "{" + elements[i];
            if (i == elements.length - 1 && !elements[i].endsWith("
            
            
            
            
            
            
            
            "purseInfoList": {
        "purseInfo": {
            "purseId": ["TRAVEL","TRAVEL","TRAVEL","TRAVEL","TRAVEL","TRAVEL","TRAVEL"]
            "purseCurrency": ["AED","CAD","AUD","EUR","USD","GBP","SGD"]
            "purseAvailableBalance": ["0.00","0.00","0.00","0.00","0.00","0.00","0.00"]
            "purseCurrentBalance": ["0.00","0.00","0.00","0.00","0.00","0.00","0.00"]
            "purseStatus": ["A","A","A","A","A","A","A",]
        },
    }



{"purseInfo": {"purseId": "TRAVEL","purseCurrency": "AED","purseAvailableBalance": "0.00","purseCurrentBalance": "0.00","purseStatus": "A"},"purseInfo": {"purseId": "TRAVEL","purseCurrency": "CAD","purseAvailableBalance": "0.00","purseCurrentBalance": "0.00","purseStatus": "A"},"purseInfo": {"purseId": "TRAVEL","purseCurrency": "AUD","purseAvailableBalance": "0.00","purseCurrentBalance": "0.00","purseStatus": "A"},"purseInfo": {"purseId": "TRAVEL","purseCurrency": "EUR","purseAvailableBalance": "0.00","purseCurrentBalance": "0.00","purseStatus": "A"},"purseInfo": {"purseId": "TRAVEL","purseCurrency": "USD","purseAvailableBalance": "0.00","purseCurrentBalance": "0.00","purseStatus": "A"},"purseInfo": {"purseId": "TRAVEL","purseCurrency": "GBP","purseAvailableBalance": "0.00","purseCurrentBalance": "0.00","purseStatus": "A"},"purseInfo": {"purseId": "TRAVEL","purseCurrency": "SGD","purseAvailableBalance": "0.00","purseCurrentBalance": "0.00","purseStatus": "A"}}



import java.util.*;

public class Main {
    public static void main(String[] args) {
        // Example JSON string input
        String jsonString = "{\"a\":{\"0\":\"d1\",\"1\":\"d2\",\"2\":\"d3\"},\"b\":{\"0\":\"e1\",\"1\":\"e2\",\"2\":\"e3\"},\"c\":{\"0\":\"f1\",\"1\":\"f2\",\"2\":\"f3\"}}";

        // Call the function to get the parallel elements
        List<List<String>> result = getParallelElements(jsonString);

        // Print the result
        for (List<String> innerList : result) {
            System.out.println(innerList);
        }
    }

    public static List<List<String>> getParallelElements(String jsonString) {
        // Manually parse the JSON string
        Map<String, Map<String, String>> jsonData = manualJsonParse(jsonString);

        // Find the maximum length of the inner JSON objects
        int maxLength = 0;
        for (Map<String, String> innerObject : jsonData.values()) {
            maxLength = Math.max(maxLength, innerObject.size());
        }

        // Initialize the result list
        List<List<String>> result = new ArrayList<>();
        for (int i = 0; i < maxLength; i++) {
            result.add(new ArrayList<>());
        }

        // Populate the result list with parallel elements
        for (Map<String, String> innerObject : jsonData.values()) {
            for (int i = 0; i < maxLength; i++) {
                String value = innerObject.get(String.valueOf(i));
                if (value != null) {
                    result.get(i).add(value);
                }
            }
        }

        return result;
    }

    public static Map<String, Map<String, String>> manualJsonParse(String jsonString) {
        // Simple manual JSON parser for the given format
        jsonString = jsonString.trim().substring(1, jsonString.length() - 1); // Remove outer {}
        String[] parts = jsonString.split("\\},\\\"");
        Map<String, Map<String, String>> result = new HashMap<>();

        for (String part : parts) {
            part = part.replaceAll("\\\"", "").replaceAll("\\{", "").replaceAll("\\}", "");
            String[] keyValuePairs = part.split(",");
            String key = keyValuePairs[0].split("\\:")[0];
            Map<String, String> innerMap = new HashMap<>();

            for (int i = 1; i < keyValuePairs.length; i++) {
                String[] pair = keyValuePairs[i].split("\\:");
                if (pair.length == 2) {
                    innerMap.put(pair[0], pair[1]);
                }
            }

            result.put(key, innerMap);
        }

        return result;
    }
}




















import java.util.*;

public class JsonTransposePureJava {
    public static void main(String[] args) {
        // Simulating the parsed JSON structure using nested Maps
        Map<String, Map<String, String>> input = new HashMap<>();

        Map<String, String> a = Map.of("x", "d1", "y", "d2", "z", "d3");
        Map<String, String> b = Map.of("x", "e1", "y", "e2", "z", "e3");
        Map<String, String> c = Map.of("x", "f1", "y", "f2", "z", "f3");

        input.put("a", a);
        input.put("b", b);
        input.put("c", c);

        // Get all keys from the first entry (assumes all inner maps have same keys)
        Set<String> innerKeys = input.values().iterator().next().keySet();

        // Prepare the result
        List<List<String>> result = new ArrayList<>();

        for (String innerKey : innerKeys) {
            List<String> row = new ArrayList<>();
            for (String outerKey : input.keySet()) {
                Map<String, String> innerMap = input.get(outerKey);
                row.add(innerMap.get(innerKey));
            }
            result.add(row);
        }

        // Print the result
        for (List<String> row : result) {
            System.out.println(row);
        }
    }
}















import org.json.JSONArray;
import org.json.JSONObject;

import java.util.*;

public class TransposeNamedJson {
    public static void main(String[] args) {
        String jsonString = """
        {
          "a": {"x": "d1", "y": "d2", "z": "d3"},
          "b": {"x": "e1", "y": "e2", "z": "e3"},
          "c": {"x": "f1", "y": "f2", "z": "f3"}
        }
        """;

        JSONObject input = new JSONObject(jsonString);

        // Get all outer keys: a, b, c
        List<String> outerKeys = new ArrayList<>(input.keySet());

        // Collect all unique inner keys: x, y, z
        Set<String> innerKeySet = input.getJSONObject(outerKeys.get(0)).keySet();

        JSONArray result = new JSONArray();

        for (String innerKey : innerKeySet) {
            JSONArray row = new JSONArray();
            for (String outerKey : outerKeys) {
                JSONObject innerObject = input.getJSONObject(outerKey);
                row.put(innerObject.getString(innerKey));
            }
            result.put(row);
        }

        System.out.println(result.toString(2));
    }
}




# Library-Management
Library Management System is a system which maintains the information about the books present in the library, their authors, the members of library to whom books are 
issued and all. This is very difficult to organize manually. Maintenance of all this information manually is a very complex task. Owing to the advancement of technology, 
organization of an Online Library becomes much simple.The maintenance of the records is made efficient, as all the records are stored in the ACCESS database, through 
which data can be retrieved easily. It makes entire process online where student can search books, staff can generate reports and do book transactions.The navigation 
control is provided in all the forms to navigate through the large amount of records. 
The Library Management has been designed to computerize and automate the operations performed over the information about the members, book issues and returns and all 
other operations. This computerization of library helps in many instances of its maintenance. It reduces the workload of management as most of the manual work done is 
reduced.
