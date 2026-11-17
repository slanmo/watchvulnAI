package platform

import "time"

func (e *Engine) PruneDeliveries() error {
	cfg, err := e.store.Config()
	if err != nil {
		return err
	}
	if cfg.DeliveryRetentionDays == 0 {
		return nil
	}
	rows, err := e.store.Deliveries()
	if err != nil {
		return err
	}
	cutoff := time.Now().AddDate(0, 0, -cfg.DeliveryRetentionDays)
	for _, d := range rows {
		if !d.CreatedAt.Before(cutoff) {
			continue
		}
		if d.Status == "pending" || (d.Status == "failed" && d.Attempts < 8) {
			continue
		}
		if _, err = e.store.db.Exec(e.store.q("DELETE FROM platform_objects WHERE kind='delivery' AND id=?"), d.ID); err != nil {
			return err
		}
	}
	return nil
}
