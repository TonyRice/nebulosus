package io.nebulosus.predicates;


import com.hazelcast.query.Predicate;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.Map;

public class KeyStartsWithPredicate implements Serializable, Predicate {

    final private String key;
    final private String startsWith;

    public KeyStartsWithPredicate(String startsWith) {
        this(null, startsWith);
    }

    public KeyStartsWithPredicate(String key, String startsWith){
        this.key = key;
        this.startsWith = startsWith;
    }

    @Override
    public boolean apply(Map.Entry entry) {
        if(key == null){
            return entry.getKey() instanceof String && ((String) entry.getKey()).startsWith(startsWith);
        }
        Object o = entry.getValue();
        Class<?> clazz = o.getClass();

        for(Field field : clazz.getDeclaredFields()) {
            if (field.getName().equals(key)) {
                try {
                    Object c = field.get(o);
                    if(c != null && c instanceof String){
                        if(((String) c).startsWith(startsWith)){
                            return true;
                        }
                    }
                } catch (IllegalAccessException e) {
                    e.printStackTrace();
                }
            }
        }
        return false;
    }
}
