package io.github.mesubash.iam.config;

import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationVersion;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.sql.DataSource;
import java.util.Arrays;

@Configuration
public class FlywayConfig {

    @Bean(initMethod = "migrate")
    @ConditionalOnProperty(prefix = "spring.flyway", name = "enabled",
            havingValue = "true", matchIfMissing = true)
    @ConditionalOnMissingBean(Flyway.class)
    public Flyway flyway(DataSource dataSource,
                         @Value("${spring.flyway.locations:classpath:db/migration}") String locations,
                         @Value("${spring.flyway.baseline-on-migrate:true}") boolean baselineOnMigrate,
                         @Value("${spring.flyway.baseline-version:0}") String baselineVersion,
                         @Value("${spring.flyway.validate-on-migrate:true}") boolean validateOnMigrate) {

        String[] resolvedLocations = Arrays.stream(locations.split(","))
                .map(String::trim)
                .filter(value -> !value.isEmpty())
                .toArray(String[]::new);

        if (resolvedLocations.length == 0) {
            resolvedLocations = new String[]{"classpath:db/migration"};
        }

        return Flyway.configure()
                .dataSource(dataSource)
                .locations(resolvedLocations)
                .baselineOnMigrate(baselineOnMigrate)
                .baselineVersion(MigrationVersion.fromVersion(baselineVersion))
                .validateOnMigrate(validateOnMigrate)
                .load();
    }
}
